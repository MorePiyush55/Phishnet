"""Threat analysis worker for processing email threat assessments."""

import json
import asyncio
import uuid
from datetime import datetime
from typing import Dict, Any, Optional
import traceback

from app.config.settings import settings
from app.config.logging import get_logger
from app.core.database import get_db
from app.core.redis_client import redis_client
from app.models.email_scan import (
    EmailScanRequest, ThreatResult, AnalysisComponentResult, 
    ScanStatus, ThreatLevel, AuditLog
)
from app.orchestrator.threat_orchestrator import ThreatOrchestrator
from app.core.metrics import worker_metrics
from app.services.websocket_manager import websocket_manager

logger = get_logger(__name__)


class ThreatAnalysisWorker:
    """Worker for processing threat analysis jobs."""
    
    def __init__(self, worker_id: Optional[str] = None):
        """Initialize threat analysis worker."""
        self.worker_id = worker_id or f"threat_worker_{uuid.uuid4().hex[:8]}"
        self.orchestrator = ThreatOrchestrator()
        self.running = False
        self.processed_count = 0
        self.error_count = 0
    
    async def start(self):
        """Start the threat analysis worker."""
        self.running = True
        logger.info(f"Starting threat analysis worker {self.worker_id}")
        
        try:
            while self.running:
                await self._process_batch()
                await asyncio.sleep(2)  # Brief pause between batches
        except KeyboardInterrupt:
            logger.info(f"Threat analysis worker {self.worker_id} interrupted")
        except Exception as e:
            logger.error(f"Threat analysis worker {self.worker_id} crashed: {e}")
            logger.error(traceback.format_exc())
        finally:
            await self._cleanup()
    
    async def stop(self):
        """Stop the threat analysis worker."""
        self.running = False
        logger.info(f"Stopping threat analysis worker {self.worker_id}")
    
    async def _process_batch(self):
        """Process a batch of threat analysis jobs."""
        try:
            # Get job from Redis queue
            job_data = await redis_client.brpop("threat_analysis_queue", timeout=5)
            
            if not job_data:
                return  # No jobs available
            
            queue_name, job_json = job_data
            job = json.loads(job_json.decode())
            
            await self._process_threat_analysis_job(job)
            
        except Exception as e:
            logger.error(f"Batch processing error in {self.worker_id}: {e}")
            self.error_count += 1
    
    async def _process_threat_analysis_job(self, job: Dict[str, Any]):
        """Process individual threat analysis job."""
        scan_request_id = job.get("scan_request_id")
        email_content = job.get("email_content")
        analysis_id = job.get("analysis_id")
        
        if not all([scan_request_id, email_content, analysis_id]):
            logger.error(f"Invalid threat analysis job: {job}")
            return
        
        start_time = datetime.utcnow()
        logger.info(f"Processing threat analysis {analysis_id} for scan {scan_request_id}")
        
        try:
            # Get scan request
            async with get_db() as db:
                scan_request = db.query(EmailScanRequest).filter(
                    EmailScanRequest.id == scan_request_id
                ).first()
                
                if not scan_request:
                    logger.error(f"Scan request {scan_request_id} not found")
                    return
                
                if scan_request.status == ScanStatus.COMPLETED:
                    logger.info(f"Scan request {scan_request_id} already completed")
                    return
            
            # Run threat analysis
            analysis_result = await self.orchestrator.analyze_email(scan_request_id, email_content)
            
            # Store results in database
            await self._store_analysis_results(scan_request_id, analysis_result)
            
            # Send real-time update via WebSocket
            await self._send_websocket_update(scan_request, analysis_result)
            
            # Check for auto-quarantine
            await self._check_auto_quarantine(scan_request, analysis_result)
            
            # Update metrics
            worker_metrics.threat_analyses_completed.inc()
            self.processed_count += 1
            
            duration = (datetime.utcnow() - start_time).total_seconds()
            logger.info(f"Threat analysis {analysis_id} completed in {duration:.2f}s")
            
        except Exception as e:
            error_msg = f"Threat analysis failed: {str(e)}"
            logger.error(f"Error in threat analysis {analysis_id}: {error_msg}")
            logger.error(traceback.format_exc())
            
            await self._handle_analysis_error(scan_request_id, error_msg)
            self.error_count += 1
            worker_metrics.threat_analysis_errors.inc()
    
    async def _store_analysis_results(
        self, 
        scan_request_id: str, 
        analysis_result: Dict[str, Any]
    ):
        """Store threat analysis results in database."""
        try:
            async with get_db() as db:
                scan_request = db.query(EmailScanRequest).filter(
                    EmailScanRequest.id == scan_request_id
                ).first()
                
                if not scan_request:
                    raise ValueError(f"Scan request {scan_request_id} not found")
                
                # Create main threat result
                threat_result = ThreatResult(
                    scan_request_id=scan_request.id,
                    threat_score=analysis_result.get("threat_score", 0.0),
                    threat_level=analysis_result.get("threat_level", ThreatLevel.SAFE),
                    confidence=analysis_result.get("confidence", 0.0),
                    phishing_indicators=analysis_result.get("phishing_indicators", []),
                    malicious_links=analysis_result.get("malicious_links", 0),
                    suspicious_attachments=analysis_result.get("suspicious_attachments", 0),
                    reputation_flags=analysis_result.get("reputation_flags", 0),
                    explanation=analysis_result.get("explanation", ""),
                    recommendations=analysis_result.get("recommendations", []),
                    analysis_duration_seconds=analysis_result.get("analysis_duration_seconds"),
                    analyzers_used=list(analysis_result.get("components", {}).keys()),
                    
                    # Component scores
                    link_analysis_score=analysis_result.get("component_scores", {}).get("link_analysis"),
                    content_analysis_score=analysis_result.get("component_scores", {}).get("gemini_llm"),
                    sender_reputation_score=analysis_result.get("component_scores", {}).get("abuseipdb"),
                    ml_model_score=None,  # TODO: Add ML model
                    llm_analysis_score=analysis_result.get("component_scores", {}).get("gemini_llm")
                )
                
                db.add(threat_result)
                db.flush()  # Get the ID
                
                # Store component results
                components = analysis_result.get("components", {})
                for component_name, component_result in components.items():
                    if isinstance(component_result, dict):
                        component_record = AnalysisComponentResult(
                            threat_result_id=threat_result.id,
                            component_name=component_name,
                            component_version="1.0",
                            score=component_result.get("score"),
                            verdict=component_result.get("verdict"),
                            confidence=component_result.get("confidence"),
                            findings=component_result.get("findings"),
                            indicators=component_result.get("indicators"),
                            metadata=component_result,
                            execution_time_ms=int(
                                component_result.get("analysis_duration", 0) * 1000
                            ) if "analysis_duration" in component_result else None,
                            error_message=component_result.get("error")
                        )
                        db.add(component_record)
                
                # Update scan request
                scan_request.status = ScanStatus.COMPLETED
                scan_request.completed_at = datetime.utcnow()
                
                # Log audit event
                audit = AuditLog(
                    user_id=scan_request.user_id,
                    scan_request_id=scan_request.id,
                    action="threat_analysis_completed",
                    resource_type="email",
                    resource_id=scan_request.gmail_message_id,
                    success=True,
                    details={
                        "threat_level": analysis_result.get("threat_level"),
                        "threat_score": analysis_result.get("threat_score"),
                        "components_used": list(components.keys()),
                        "analysis_duration": analysis_result.get("analysis_duration_seconds")
                    },
                    legal_basis="legitimate_interest"
                )
                db.add(audit)
                
                db.commit()
                
                logger.info(f"Stored analysis results for scan {scan_request_id}")
                
        except Exception as e:
            logger.error(f"Failed to store analysis results for {scan_request_id}: {e}")
            raise
    
    async def _send_websocket_update(
        self,
        scan_request: EmailScanRequest,
        analysis_result: Dict[str, Any]
    ):
        """Send real-time update via WebSocket."""
        try:
            # Prepare websocket message
            ws_message = {
                "type": "threat_analysis_complete",
                "scan_request_id": str(scan_request.id),
                "user_id": scan_request.user_id,
                "gmail_message_id": scan_request.gmail_message_id,
                "threat_level": analysis_result.get("threat_level"),
                "threat_score": analysis_result.get("threat_score"),
                "confidence": analysis_result.get("confidence"),
                "explanation": analysis_result.get("explanation"),
                "recommendations": analysis_result.get("recommendations", [])[:3],  # Top 3
                "phishing_indicators": analysis_result.get("phishing_indicators", [])[:5],  # Top 5
                "timestamp": datetime.utcnow().isoformat()
            }
            
            # Send to user's WebSocket connection
            await websocket_manager.send_to_user(scan_request.user_id, ws_message)
            
            logger.debug(f"Sent WebSocket update for scan {scan_request.id}")
            
        except Exception as e:
            logger.error(f"Failed to send WebSocket update: {e}")
    
    async def _check_auto_quarantine(
        self,
        scan_request: EmailScanRequest,
        analysis_result: Dict[str, Any]
    ):
        """Check if email should be auto-quarantined based on policy."""
        try:
            threat_level = analysis_result.get("threat_level")
            threat_score = analysis_result.get("threat_score", 0.0)
            
            # Auto-quarantine policy: CRITICAL or HIGH threat
            should_quarantine = (
                threat_level in [ThreatLevel.CRITICAL, ThreatLevel.HIGH] or
                threat_score >= 0.8
            )
            
            if should_quarantine:
                # Queue for auto-quarantine
                quarantine_job = {
                    "scan_request_id": str(scan_request.id),
                    "user_id": scan_request.user_id,
                    "gmail_message_id": scan_request.gmail_message_id,
                    "action_type": "quarantine",
                    "action_method": "auto",
                    "threat_level": threat_level,
                    "threat_score": threat_score,
                    "policy_rule": "auto_quarantine_high_threat"
                }
                
                await redis_client.lpush("quarantine_actions_queue", json.dumps(quarantine_job))
                
                logger.info(f"Queued auto-quarantine for scan {scan_request.id} (threat: {threat_level})")
            
        except Exception as e:
            logger.error(f"Auto-quarantine check failed for scan {scan_request.id}: {e}")
    
    async def _handle_analysis_error(self, scan_request_id: str, error_message: str):
        """Handle threat analysis error."""
        try:
            async with get_db() as db:
                scan_request = db.query(EmailScanRequest).filter(
                    EmailScanRequest.id == scan_request_id
                ).first()
                
                if scan_request:
                    scan_request.status = ScanStatus.FAILED
                    scan_request.completed_at = datetime.utcnow()
                    scan_request.error_message = error_message
                    
                    # Log audit event
                    audit = AuditLog(
                        user_id=scan_request.user_id,
                        scan_request_id=scan_request.id,
                        action="threat_analysis_failed",
                        resource_type="email",
                        resource_id=scan_request.gmail_message_id,
                        success=False,
                        error_message=error_message,
                        details={
                            "worker_id": self.worker_id,
                            "error": error_message
                        }
                    )
                    db.add(audit)
                    
                    db.commit()
                    
        except Exception as e:
            logger.error(f"Failed to handle analysis error for {scan_request_id}: {e}")
    
    async def _cleanup(self):
        """Cleanup worker resources."""
        logger.info(f"Threat analysis worker {self.worker_id} cleanup - processed: {self.processed_count}, errors: {self.error_count}")


async def main():
    """Main threat analysis worker entry point."""
    # Create worker instances based on concurrency setting
    concurrency = int(settings.WORKER_CONCURRENCY or 2)
    
    # Create workers
    workers = []
    for i in range(concurrency):
        worker = ThreatAnalysisWorker(f"threat_worker_{i+1}")
        workers.append(worker)
    
    try:
        # Start all workers
        worker_tasks = [asyncio.create_task(worker.start()) for worker in workers]
        
        logger.info(f"Started {len(workers)} threat analysis workers")
        
        # Wait for all workers
        await asyncio.gather(*worker_tasks)
        
    except KeyboardInterrupt:
        logger.info("Shutting down threat analysis workers...")
        
        # Stop all workers
        for worker in workers:
            await worker.stop()
        
        logger.info("Threat analysis workers shutdown complete")


if __name__ == "__main__":
    asyncio.run(main())
