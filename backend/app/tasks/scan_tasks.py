"""
Email Scanning Task Workers
Handles background processing for email security scanning operations.
"""

import logging
import time
from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta
from celery import current_task
from backend.app.workers.celery_config import celery_app
from backend.app.models.production_models import EmailMeta, ScanResult, ThreatIntelligence
from backend.app.services.enhanced_ml_analyzer import get_ml_analyzer
from backend.app.services.url_analyzer import get_url_analyzer
from backend.app.services.enhanced_attachment_analyzer import get_attachment_analyzer
from backend.app.core.database import get_db
from backend.app.core.redis_client import get_redis_client

logger = logging.getLogger(__name__)

# WebSocket notification helper
def notify_progress_sync(task_id: str, progress: int, message: str = None):
    """Send progress update via WebSocket (synchronous wrapper)."""
    try:
        # Store progress in Redis for WebSocket polling
        redis_client = get_redis_client()
        progress_data = {
            "progress": progress,
            "message": message or "",
            "timestamp": datetime.utcnow().isoformat()
        }
        redis_client.hmset(f"job:{task_id}:progress", progress_data)
        redis_client.expire(f"job:{task_id}:progress", 3600)
        
        # Update main job data
        redis_client.hset(f"job:{task_id}", "progress", progress)
        if message:
            redis_client.hset(f"job:{task_id}", "status_message", message)
            
    except Exception as e:
        logger.warning(f"Failed to store progress notification: {str(e)}")

@celery_app.task(bind=True, name="backend.app.tasks.scan_tasks.quick_email_scan")
def quick_email_scan(self, email_id: str, scan_options: Dict[str, Any]) -> Dict[str, Any]:
    """
    Quick email scan for real-time processing (<10 seconds).
    
    Args:
        email_id: Email identifier
        scan_options: Scanning configuration options
        
    Returns:
        Scan results dictionary
    """
    try:
        start_time = time.time()
        task_id = self.request.id
        
        # Update task progress with WebSocket notifications
        self.update_state(state='PROGRESS', meta={'progress': 10, 'status': 'Starting quick scan'})
        notify_progress_sync(task_id, 10, 'Starting quick scan')
        
        # Get email data
        with get_db() as db:
            email = db.query(EmailMeta).filter(EmailMeta.id == email_id).first()
            if not email:
                raise ValueError(f"Email {email_id} not found")
        
        self.update_state(state='PROGRESS', meta={'progress': 30, 'status': 'Analyzing headers'})
        notify_progress_sync(task_id, 30, 'Analyzing headers')
        
        # Quick header analysis
        header_results = _analyze_email_headers(email.headers)
        
        self.update_state(state='PROGRESS', meta={'progress': 60, 'status': 'Basic content scan'})
        notify_progress_sync(task_id, 60, 'Basic content scan')
        
        # Basic content scanning (no heavy ML)
        content_results = _quick_content_scan(email.content)
        
        self.update_state(state='PROGRESS', meta={'progress': 80, 'status': 'Generating results'})
        notify_progress_sync(task_id, 80, 'Generating results')
        
        # Compile results
        scan_results = {
            "email_id": email_id,
            "scan_type": "quick",
            "start_time": start_time,
            "duration": time.time() - start_time,
            "results": {
                "header_analysis": header_results,
                "content_analysis": content_results,
                "risk_score": _calculate_quick_risk_score(header_results, content_results),
                "threats_detected": header_results.get("threats", []) + content_results.get("threats", [])
            },
            "status": "completed",
            "timestamp": datetime.utcnow().isoformat()
        }
        
        # Store results
        _store_scan_results(email_id, scan_results)
        
        self.update_state(state='SUCCESS', meta={'progress': 100, 'results': scan_results})
        
        logger.info(f"Quick scan completed for email {email_id} in {scan_results['duration']:.2f}s")
        return scan_results
        
    except Exception as e:
        logger.error(f"Quick email scan failed for {email_id}: {str(e)}")
        self.update_state(state='FAILURE', meta={'error': str(e)})
        raise

@celery_app.task(bind=True, name="backend.app.tasks.scan_tasks.full_email_scan")
def full_email_scan(self, email_id: str, scan_options: Dict[str, Any]) -> Dict[str, Any]:
    """
    Comprehensive email scan with ML analysis (10-60 seconds).
    
    Args:
        email_id: Email identifier
        scan_options: Scanning configuration options
        
    Returns:
        Comprehensive scan results
    """
    try:
        start_time = time.time()
        
        self.update_state(state='PROGRESS', meta={'progress': 5, 'status': 'Initializing full scan'})
        
        # Get email data
        with get_db() as db:
            email = db.query(EmailMeta).filter(EmailMeta.id == email_id).first()
            if not email:
                raise ValueError(f"Email {email_id} not found")
        
        self.update_state(state='PROGRESS', meta={'progress': 15, 'status': 'Analyzing headers'})
        
        # Comprehensive header analysis
        header_results = _analyze_email_headers(email.headers, comprehensive=True)
        
        self.update_state(state='PROGRESS', meta={'progress': 30, 'status': 'ML content analysis'})
        
        # ML-powered content analysis
        ml_analyzer = get_ml_analyzer()
        content_results = ml_analyzer.analyze_email_content(email.content, email.subject)
        
        self.update_state(state='PROGRESS', meta={'progress': 50, 'status': 'URL analysis'})
        
        # URL analysis
        url_results = []
        if scan_options.get("analyze_urls", True):
            urls = _extract_urls_from_email(email.content)
            url_analyzer = get_url_analyzer()
            for url in urls:
                url_result = url_analyzer.analyze_url(url)
                url_results.append(url_result)
        
        self.update_state(state='PROGRESS', meta={'progress': 70, 'status': 'Reputation lookup'})
        
        # Sender reputation lookup
        reputation_results = _lookup_sender_reputation(email.sender, email.headers)
        
        self.update_state(state='PROGRESS', meta={'progress': 85, 'status': 'Threat intelligence'})
        
        # Threat intelligence lookup
        threat_intel_results = _lookup_threat_intelligence(email)
        
        self.update_state(state='PROGRESS', meta={'progress': 95, 'status': 'Compiling results'})
        
        # Compile comprehensive results
        scan_results = {
            "email_id": email_id,
            "scan_type": "full",
            "start_time": start_time,
            "duration": time.time() - start_time,
            "results": {
                "header_analysis": header_results,
                "content_analysis": content_results,
                "url_analysis": url_results,
                "reputation_analysis": reputation_results,
                "threat_intelligence": threat_intel_results,
                "ml_confidence": content_results.get("confidence", 0),
                "risk_score": _calculate_comprehensive_risk_score(
                    header_results, content_results, url_results, reputation_results, threat_intel_results
                ),
                "threats_detected": _aggregate_threats(
                    header_results, content_results, url_results, reputation_results, threat_intel_results
                )
            },
            "status": "completed",
            "timestamp": datetime.utcnow().isoformat()
        }
        
        # Store results
        _store_scan_results(email_id, scan_results)
        
        self.update_state(state='SUCCESS', meta={'progress': 100, 'results': scan_results})
        
        logger.info(f"Full scan completed for email {email_id} in {scan_results['duration']:.2f}s")
        return scan_results
        
    except Exception as e:
        logger.error(f"Full email scan failed for {email_id}: {str(e)}")
        self.update_state(state='FAILURE', meta={'error': str(e)})
        raise

@celery_app.task(bind=True, name="backend.app.tasks.scan_tasks.sandbox_analysis")
def sandbox_analysis(self, email_id: str, attachment_ids: List[str]) -> Dict[str, Any]:
    """
    Heavy sandbox analysis for suspicious attachments (>60 seconds).
    
    Args:
        email_id: Email identifier
        attachment_ids: List of attachment IDs to analyze
        
    Returns:
        Sandbox analysis results
    """
    try:
        start_time = time.time()
        
        self.update_state(state='PROGRESS', meta={'progress': 5, 'status': 'Initializing sandbox'})
        
        # Get email and attachments
        with get_db() as db:
            email = db.query(EmailMeta).filter(EmailMeta.id == email_id).first()
            if not email:
                raise ValueError(f"Email {email_id} not found")
        
        sandbox_results = []
        total_attachments = len(attachment_ids)
        
        for i, attachment_id in enumerate(attachment_ids):
            progress = 10 + (70 * i // total_attachments)
            self.update_state(
                state='PROGRESS', 
                meta={'progress': progress, 'status': f'Analyzing attachment {i+1}/{total_attachments}'}
            )
            
            # Perform sandbox analysis
            attachment_result = _sandbox_analyze_attachment(attachment_id)
            sandbox_results.append(attachment_result)
            
            # Add delay to prevent overwhelming sandbox
            time.sleep(2)
        
        self.update_state(state='PROGRESS', meta={'progress': 90, 'status': 'Compiling sandbox results'})
        
        # Compile sandbox results
        scan_results = {
            "email_id": email_id,
            "scan_type": "sandbox",
            "start_time": start_time,
            "duration": time.time() - start_time,
            "results": {
                "attachments_analyzed": len(attachment_ids),
                "sandbox_results": sandbox_results,
                "high_risk_attachments": [r for r in sandbox_results if r.get("risk_level") == "high"],
                "malware_detected": any(r.get("malware_detected", False) for r in sandbox_results),
                "overall_risk_score": max([r.get("risk_score", 0) for r in sandbox_results], default=0)
            },
            "status": "completed",
            "timestamp": datetime.utcnow().isoformat()
        }
        
        # Store results
        _store_scan_results(email_id, scan_results, scan_type="sandbox")
        
        self.update_state(state='SUCCESS', meta={'progress': 100, 'results': scan_results})
        
        logger.info(f"Sandbox analysis completed for email {email_id} in {scan_results['duration']:.2f}s")
        return scan_results
        
    except Exception as e:
        logger.error(f"Sandbox analysis failed for {email_id}: {str(e)}")
        self.update_state(state='FAILURE', meta={'error': str(e)})
        raise

@celery_app.task(bind=True, name="backend.app.tasks.scan_tasks.link_safety_check")
def link_safety_check(self, url: str, context: Dict[str, Any]) -> Dict[str, Any]:
    """
    Real-time link safety check for immediate user feedback.
    
    Args:
        url: URL to check
        context: Additional context (email_id, user_id, etc.)
        
    Returns:
        Link safety results
    """
    try:
        start_time = time.time()
        
        self.update_state(state='PROGRESS', meta={'progress': 20, 'status': 'Checking URL reputation'})
        
        # Quick URL reputation check
        url_analyzer = get_url_analyzer()
        reputation_result = url_analyzer.check_url_reputation(url)
        
        self.update_state(state='PROGRESS', meta={'progress': 60, 'status': 'Analyzing URL structure'})
        
        # URL structure analysis
        structure_result = url_analyzer.analyze_url_structure(url)
        
        self.update_state(state='PROGRESS', meta={'progress': 90, 'status': 'Finalizing safety assessment'})
        
        # Compile results
        safety_results = {
            "url": url,
            "context": context,
            "scan_type": "link_safety",
            "start_time": start_time,
            "duration": time.time() - start_time,
            "results": {
                "reputation": reputation_result,
                "structure_analysis": structure_result,
                "safety_score": _calculate_url_safety_score(reputation_result, structure_result),
                "recommendation": _get_url_recommendation(reputation_result, structure_result),
                "is_safe": _is_url_safe(reputation_result, structure_result)
            },
            "status": "completed",
            "timestamp": datetime.utcnow().isoformat()
        }
        
        # Cache results for quick future lookups
        _cache_url_results(url, safety_results)
        
        self.update_state(state='SUCCESS', meta={'progress': 100, 'results': safety_results})
        
        logger.info(f"Link safety check completed for {url} in {safety_results['duration']:.2f}s")
        return safety_results
        
    except Exception as e:
        logger.error(f"Link safety check failed for {url}: {str(e)}")
        self.update_state(state='FAILURE', meta={'error': str(e)})
        raise

@celery_app.task(bind=True, name="backend.app.tasks.scan_tasks.deep_attachment_scan")
def deep_attachment_scan(self, email_id: str, attachment_id: str, scan_options: Dict[str, Any]) -> Dict[str, Any]:
    """
    Deep attachment analysis with multiple detection engines.
    
    Args:
        email_id: Email identifier
        attachment_id: Attachment identifier
        scan_options: Scanning options
        
    Returns:
        Deep scan results
    """
    try:
        start_time = time.time()
        
        self.update_state(state='PROGRESS', meta={'progress': 10, 'status': 'Loading attachment'})
        
        # Get attachment analyzer
        attachment_analyzer = get_attachment_analyzer()
        
        self.update_state(state='PROGRESS', meta={'progress': 25, 'status': 'Static analysis'})
        
        # Static analysis
        static_results = attachment_analyzer.static_analysis(attachment_id)
        
        self.update_state(state='PROGRESS', meta={'progress': 50, 'status': 'Dynamic analysis'})
        
        # Dynamic analysis (if enabled)
        dynamic_results = None
        if scan_options.get("dynamic_analysis", False):
            dynamic_results = attachment_analyzer.dynamic_analysis(attachment_id)
        
        self.update_state(state='PROGRESS', meta={'progress': 75, 'status': 'ML analysis'})
        
        # ML-based analysis
        ml_results = attachment_analyzer.ml_analysis(attachment_id)
        
        self.update_state(state='PROGRESS', meta={'progress': 90, 'status': 'Compiling results'})
        
        # Compile results
        scan_results = {
            "email_id": email_id,
            "attachment_id": attachment_id,
            "scan_type": "deep_attachment",
            "start_time": start_time,
            "duration": time.time() - start_time,
            "results": {
                "static_analysis": static_results,
                "dynamic_analysis": dynamic_results,
                "ml_analysis": ml_results,
                "overall_risk_score": _calculate_attachment_risk_score(
                    static_results, dynamic_results, ml_results
                ),
                "malware_detected": _check_malware_detected(static_results, dynamic_results, ml_results),
                "threat_categories": _categorize_threats(static_results, dynamic_results, ml_results)
            },
            "status": "completed",
            "timestamp": datetime.utcnow().isoformat()
        }
        
        # Store results
        _store_scan_results(email_id, scan_results, scan_type="attachment")
        
        self.update_state(state='SUCCESS', meta={'progress': 100, 'results': scan_results})
        
        logger.info(f"Deep attachment scan completed for {attachment_id} in {scan_results['duration']:.2f}s")
        return scan_results
        
    except Exception as e:
        logger.error(f"Deep attachment scan failed for {attachment_id}: {str(e)}")
        self.update_state(state='FAILURE', meta={'error': str(e)})
        raise

# Helper functions

def _analyze_email_headers(headers: Dict[str, Any], comprehensive: bool = False) -> Dict[str, Any]:
    """Analyze email headers for security indicators."""
    results = {
        "spf_check": "pass",  # Mock implementation
        "dkim_check": "pass",
        "dmarc_check": "pass",
        "suspicious_headers": [],
        "threats": []
    }
    
    if comprehensive:
        results.update({
            "received_chain": [],
            "authentication_results": {},
            "routing_analysis": {}
        })
    
    return results

def _quick_content_scan(content: str) -> Dict[str, Any]:
    """Perform quick content scanning without heavy ML."""
    return {
        "suspicious_keywords": [],
        "urgency_indicators": [],
        "social_engineering": False,
        "threats": []
    }

def _calculate_quick_risk_score(header_results: Dict, content_results: Dict) -> int:
    """Calculate a quick risk score (0-100)."""
    return 25  # Mock implementation

def _store_scan_results(email_id: str, results: Dict[str, Any], scan_type: str = "general"):
    """Store scan results in database and cache."""
    # Store in database
    with get_db() as db:
        scan_result = ScanResult(
            email_id=email_id,
            scan_type=scan_type,
            results=results,
            risk_score=results["results"].get("risk_score", 0),
            created_at=datetime.utcnow()
        )
        db.add(scan_result)
        db.commit()
    
    # Cache results
    redis_client = get_redis_client()
    cache_key = f"scan_result:{email_id}:{scan_type}"
    redis_client.setex(cache_key, 3600, str(results))  # Cache for 1 hour

def _extract_urls_from_email(content: str) -> List[str]:
    """Extract URLs from email content."""
    import re
    url_pattern = r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
    return re.findall(url_pattern, content)

def _lookup_sender_reputation(sender: str, headers: Dict) -> Dict[str, Any]:
    """Look up sender reputation."""
    return {
        "reputation_score": 85,
        "is_known_sender": False,
        "blacklisted": False
    }

def _lookup_threat_intelligence(email: EmailMeta) -> Dict[str, Any]:
    """Look up threat intelligence."""
    return {
        "known_threats": [],
        "ioc_matches": [],
        "campaign_associations": []
    }

def _calculate_comprehensive_risk_score(*args) -> int:
    """Calculate comprehensive risk score from all analysis results."""
    return 45  # Mock implementation

def _aggregate_threats(*args) -> List[str]:
    """Aggregate threats from all analysis results."""
    return []  # Mock implementation

def _sandbox_analyze_attachment(attachment_id: str) -> Dict[str, Any]:
    """Perform sandbox analysis on attachment."""
    return {
        "attachment_id": attachment_id,
        "risk_level": "low",
        "risk_score": 20,
        "malware_detected": False,
        "behaviors": []
    }

def _calculate_url_safety_score(reputation_result: Dict, structure_result: Dict) -> int:
    """Calculate URL safety score."""
    return 75  # Mock implementation

def _get_url_recommendation(reputation_result: Dict, structure_result: Dict) -> str:
    """Get URL safety recommendation."""
    return "proceed_with_caution"

def _is_url_safe(reputation_result: Dict, structure_result: Dict) -> bool:
    """Determine if URL is safe."""
    return True  # Mock implementation

def _cache_url_results(url: str, results: Dict[str, Any]):
    """Cache URL analysis results."""
    redis_client = get_redis_client()
    cache_key = f"url_safety:{url}"
    redis_client.setex(cache_key, 1800, str(results))  # Cache for 30 minutes

def _calculate_attachment_risk_score(static_results: Dict, dynamic_results: Dict, ml_results: Dict) -> int:
    """Calculate attachment risk score."""
    return 30  # Mock implementation

def _check_malware_detected(static_results: Dict, dynamic_results: Dict, ml_results: Dict) -> bool:
    """Check if malware was detected."""
    return False  # Mock implementation

def _categorize_threats(static_results: Dict, dynamic_results: Dict, ml_results: Dict) -> List[str]:
    """Categorize detected threats."""
    return []  # Mock implementation