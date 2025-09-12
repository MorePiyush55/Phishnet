#!/usr/bin/env python3
"""
Secure Sandbox Worker for Headless Browser Analysis

This worker runs inside a secure container to analyze potentially dangerous web pages.
It captures screenshots, DOM snapshots, network logs, and JavaScript console output
using both bot and real user agents to detect cloaking behavior.

Security Features:
- Runs as non-root user
- No persistent storage
- Network egress controlled
- Resource limits enforced
- Ephemeral execution
"""

import asyncio
import json
import logging
import os
import signal
import sys
import tempfile
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple
import uuid

import structlog
from playwright.async_api import async_playwright, Page, Browser, BrowserContext
import aiohttp
from PIL import Image
import boto3
from google.cloud import storage as gcs
import redis
from artifact_storage import get_artifact_manager, ArtifactMetadata

# Configure structured logging
structlog.configure(
    processors=[
        structlog.stdlib.filter_by_level,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.TimeStamper(fmt="ISO"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        structlog.processors.UnicodeDecoder(),
        structlog.processors.JSONRenderer()
    ],
    context_class=dict,
    logger_factory=structlog.stdlib.LoggerFactory(),
    wrapper_class=structlog.stdlib.BoundLogger,
    cache_logger_on_first_use=True,
)

logger = structlog.get_logger(__name__)


class SandboxSecurityError(Exception):
    """Raised when security constraints are violated."""
    pass


class SandboxTimeoutError(Exception):
    """Raised when sandbox execution times out."""
    pass


class NetworkCapture:
    """Captures network traffic during page loading."""
    
    def __init__(self):
        self.requests: List[Dict] = []
        self.responses: List[Dict] = []
        self.failed_requests: List[Dict] = []
    
    async def setup_listeners(self, page: Page):
        """Set up network event listeners."""
        page.on("request", self._on_request)
        page.on("response", self._on_response)
        page.on("requestfailed", self._on_request_failed)
    
    def _on_request(self, request):
        """Handle request event."""
        self.requests.append({
            "url": request.url,
            "method": request.method,
            "headers": dict(request.headers),
            "timestamp": datetime.utcnow().isoformat(),
            "resource_type": request.resource_type
        })
    
    def _on_response(self, response):
        """Handle response event."""
        self.responses.append({
            "url": response.url,
            "status": response.status,
            "headers": dict(response.headers),
            "timestamp": datetime.utcnow().isoformat(),
            "ok": response.ok
        })
    
    def _on_request_failed(self, request):
        """Handle failed request event."""
        self.failed_requests.append({
            "url": request.url,
            "method": request.method,
            "failure": request.failure,
            "timestamp": datetime.utcnow().isoformat()
        })


class JSConsoleCapture:
    """Captures JavaScript console logs and errors."""
    
    def __init__(self):
        self.logs: List[Dict] = []
        self.errors: List[Dict] = []
    
    async def setup_listeners(self, page: Page):
        """Set up console event listeners."""
        page.on("console", self._on_console)
        page.on("pageerror", self._on_page_error)
    
    def _on_console(self, msg):
        """Handle console message."""
        self.logs.append({
            "type": msg.type,
            "text": msg.text,
            "location": msg.location,
            "timestamp": datetime.utcnow().isoformat()
        })
    
    def _on_page_error(self, error):
        """Handle page error."""
        self.errors.append({
            "message": str(error),
            "timestamp": datetime.utcnow().isoformat()
        })


class SandboxAnalysisResult:
    """Container for sandbox analysis results."""
    
    def __init__(self, job_id: str, target_url: str):
        self.job_id = job_id
        self.target_url = target_url
        self.start_time = datetime.utcnow()
        self.end_time: Optional[datetime] = None
        
        # Analysis data
        self.bot_user_analysis: Optional[Dict] = None
        self.real_user_analysis: Optional[Dict] = None
        self.cloaking_detected = False
        self.cloaking_evidence: List[str] = []
        self.security_findings: List[str] = []
        
        # Local artifact paths (temporary)
        self.bot_user_screenshot_path: Optional[str] = None
        self.real_user_screenshot_path: Optional[str] = None
        self.bot_user_dom_path: Optional[str] = None
        self.real_user_dom_path: Optional[str] = None
        self.network_logs: Dict[str, Any] = {}
        self.console_logs: Dict[str, Any] = {}
        
        # Cloud storage artifacts
        self.artifacts: List[ArtifactMetadata] = []
        self.archive_artifact_id: Optional[str] = None
        
        # Security events
        self.security_violations: List[str] = []
        self.blocked_requests: List[str] = []
        
        # Metadata
        self.error: Optional[str] = None
        self.timeout = False
        self.duration_ms: Optional[int] = None
        self.analysis_time: Optional[datetime] = None
    
    def finalize(self):
        """Finalize the analysis result."""
        self.end_time = datetime.utcnow()
        self.analysis_time = self.end_time
        if self.start_time:
            self.duration_ms = int((self.end_time - self.start_time).total_seconds() * 1000)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "job_id": self.job_id,
            "target_url": self.target_url,
            "start_time": self.start_time.isoformat() if self.start_time else None,
            "end_time": self.end_time.isoformat() if self.end_time else None,
            "analysis_time": self.analysis_time.isoformat() if self.analysis_time else None,
            "duration_ms": self.duration_ms,
            "bot_user_analysis": self.bot_user_analysis,
            "real_user_analysis": self.real_user_analysis,
            "cloaking_detected": self.cloaking_detected,
            "cloaking_evidence": self.cloaking_evidence,
            "security_findings": self.security_findings,
            "network_logs": self.network_logs,
            "console_logs": self.console_logs,
            "artifacts": [artifact.to_dict() for artifact in self.artifacts],
            "archive_artifact_id": self.archive_artifact_id,
            "security": {
                "violations": self.security_violations,
                "blocked_requests": self.blocked_requests
            },
            "error": self.error,
            "timeout": self.timeout
        }


class SandboxWorker:
    """Secure sandbox worker for analyzing web pages."""
    
    # Security constraints
    MAX_EXECUTION_TIME = 120  # seconds
    MAX_MEMORY_MB = 512
    MAX_SCREENSHOT_SIZE = (1920, 1080)
    BLOCKED_DOMAINS = {
        'gmail.com', 'outlook.com', 'yahoo.com',  # Email providers
        'login.microsoftonline.com', 'accounts.google.com',  # SSO providers
        'facebook.com', 'twitter.com', 'linkedin.com',  # Social networks
        'dropbox.com', 'drive.google.com', 'onedrive.com'  # Cloud storage
    }
    
    # User agents for cloaking detection
    BOT_USER_AGENT = "Mozilla/5.0 (compatible; PhishNetBot/1.0; +https://phishnet.security/bot)"
    REAL_USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36"
    
    def __init__(self):
        """Initialize sandbox worker."""
        self.job_id = str(uuid.uuid4())
        self.artifacts_dir = Path("/tmp/sandbox/artifacts")
        self.logs_dir = Path("/tmp/sandbox/logs")
        
        # Ensure directories exist
        self.artifacts_dir.mkdir(parents=True, exist_ok=True)
        self.logs_dir.mkdir(parents=True, exist_ok=True)
        
        # Artifact storage manager
        self.artifact_manager = get_artifact_manager()
        
        # Redis client for job queue
        self.redis_client = None
        self._init_redis_client()
    
    def _init_redis_client(self):
        """Initialize Redis client for job queue."""
        try:
            redis_url = os.getenv('REDIS_URL', 'redis://localhost:6379/0')
            self.redis_client = redis.from_url(redis_url, decode_responses=True)
            self.redis_client.ping()
            logger.info("Redis client initialized")
        except Exception as e:
            logger.warning("Failed to initialize Redis client", error=str(e))
    
    async def analyze_url(self, target_url: str, job_id: Optional[str] = None) -> SandboxAnalysisResult:
        """
        Analyze a URL using both bot and real user agents.
        
        Args:
            target_url: URL to analyze
            job_id: Optional job ID (generates one if not provided)
            
        Returns:
            SandboxAnalysisResult containing analysis data and artifacts
        """
        if job_id:
            self.job_id = job_id
        
        result = SandboxAnalysisResult(self.job_id, target_url)
        
        # Security: Validate URL
        if not await self._validate_url(target_url):
            result.error = "URL failed security validation"
            result.security_violations.append("Blocked domain or suspicious URL")
            result.finalize()
            return result
        
        # Set execution timeout
        timeout_task = asyncio.create_task(asyncio.sleep(self.MAX_EXECUTION_TIME))
        analysis_task = asyncio.create_task(self._perform_analysis(target_url, result))
        
        try:
            # Race between analysis and timeout
            done, pending = await asyncio.wait(
                [timeout_task, analysis_task],
                return_when=asyncio.FIRST_COMPLETED
            )
            
            # Cancel pending tasks
            for task in pending:
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass
            
            if timeout_task in done:
                result.timeout = True
                result.error = "Analysis timed out"
                logger.warning("Analysis timed out", job_id=self.job_id, url=target_url)
            else:
                # Analysis completed
                await analysis_task
                
        except Exception as e:
            result.error = f"Analysis failed: {str(e)}"
            logger.error("Analysis failed", job_id=self.job_id, url=target_url, error=str(e))
        
        result.finalize()
        
        # Upload artifacts to cloud storage
        await self._upload_artifacts(result)
        
        return result
    
    async def _validate_url(self, url: str) -> bool:
        """Validate URL against security constraints."""
        try:
            from urllib.parse import urlparse
            parsed = urlparse(url)
            
            # Check for blocked domains
            domain = parsed.netloc.lower()
            for blocked in self.BLOCKED_DOMAINS:
                if blocked in domain:
                    logger.warning("Blocked domain detected", domain=domain, url=url)
                    return False
            
            # Check for localhost/private IPs
            if any(private in domain for private in ['localhost', '127.0.0.1', '192.168.', '10.', '172.']):
                logger.warning("Private/localhost URL blocked", domain=domain)
                return False
            
            # Check for suspicious schemes
            if parsed.scheme not in ['http', 'https']:
                logger.warning("Suspicious URL scheme", scheme=parsed.scheme)
                return False
            
            return True
            
        except Exception as e:
            logger.error("URL validation failed", url=url, error=str(e))
            return False
    
    async def _perform_analysis(self, target_url: str, result: SandboxAnalysisResult):
        """Perform the actual browser analysis."""
        async with async_playwright() as p:
            # Launch browser with security settings
            browser = await p.chromium.launch(
                headless=True,
                args=[
                    '--no-sandbox',
                    '--disable-setuid-sandbox',
                    '--disable-dev-shm-usage',
                    '--disable-gpu',
                    '--disable-extensions',
                    '--disable-plugins',
                    '--disable-images',  # Save bandwidth
                    '--disable-background-timer-throttling',
                    '--disable-renderer-backgrounding',
                    '--disable-backgrounding-occluded-windows',
                    '--memory-pressure-off',
                    f'--max-memory-usage={self.MAX_MEMORY_MB}',
                    '--no-first-run',
                    '--no-default-browser-check',
                    '--disable-default-apps',
                    '--disable-component-extensions-with-background-pages'
                ]
            )
            
            try:
                # Analyze with bot user agent
                logger.info("Starting bot analysis", job_id=self.job_id, url=target_url)
                result.bot_analysis = await self._analyze_with_user_agent(
                    browser, target_url, self.BOT_USER_AGENT, "bot"
                )
                
                # Analyze with real user agent
                logger.info("Starting user analysis", job_id=self.job_id, url=target_url)
                result.user_analysis = await self._analyze_with_user_agent(
                    browser, target_url, self.REAL_USER_AGENT, "user"
                )
                
                # Detect cloaking
                await self._detect_cloaking(result)
                
            finally:
                await browser.close()
    
    async def _analyze_with_user_agent(self, browser: Browser, url: str, user_agent: str, agent_type: str) -> Dict[str, Any]:
        """Analyze URL with specific user agent."""
        # Create new context for each analysis
        context = await browser.new_context(
            user_agent=user_agent,
            viewport={"width": 1920, "height": 1080},
            java_script_enabled=True,
            permissions=[]  # No permissions granted
        )
        
        # Set up captures
        network_capture = NetworkCapture()
        console_capture = JSConsoleCapture()
        
        try:
            page = await context.new_page()
            
            # Set up event listeners
            await network_capture.setup_listeners(page)
            await console_capture.setup_listeners(page)
            
            # Navigate to page
            start_time = time.time()
            response = await page.goto(url, wait_until='networkidle', timeout=30000)
            load_time = time.time() - start_time
            
            # Wait for JavaScript execution
            await asyncio.sleep(2)
            
            # Capture screenshot
            screenshot_path = self.artifacts_dir / f"{self.job_id}_{agent_type}_screenshot.png"
            await page.screenshot(
                path=screenshot_path,
                full_page=True,
                type='png'
            )
            
            # Store screenshot path in result
            if agent_type == "bot":
                result.bot_screenshot_path = str(screenshot_path)
            else:
                result.user_screenshot_path = str(screenshot_path)
            
            # Capture DOM snapshot
            dom_content = await page.content()
            dom_path = self.artifacts_dir / f"{self.job_id}_{agent_type}_dom.html"
            with open(dom_path, 'w', encoding='utf-8') as f:
                f.write(dom_content)
            
            result.dom_snapshots[agent_type] = str(dom_path)
            
            # Store network and console logs
            result.network_logs[agent_type] = {
                "requests": network_capture.requests,
                "responses": network_capture.responses,
                "failed_requests": network_capture.failed_requests
            }
            
            result.console_logs[agent_type] = {
                "logs": console_capture.logs,
                "errors": console_capture.errors
            }
            
            # Get page metrics
            metrics = await page.evaluate('''() => {
                return {
                    url: window.location.href,
                    title: document.title,
                    readyState: document.readyState,
                    referrer: document.referrer,
                    cookies: document.cookie,
                    localStorage: Object.keys(localStorage || {}),
                    sessionStorage: Object.keys(sessionStorage || {}),
                    scripts: Array.from(document.scripts).map(s => s.src).filter(Boolean),
                    forms: Array.from(document.forms).map(f => ({
                        action: f.action,
                        method: f.method,
                        elements: f.elements.length
                    })),
                    links: Array.from(document.links).map(l => l.href).slice(0, 50)
                };
            }''')
            
            return {
                "user_agent": user_agent,
                "load_time": load_time,
                "final_url": page.url,
                "status_code": response.status if response else None,
                "metrics": metrics,
                "timestamp": datetime.utcnow().isoformat()
            }
            
        finally:
            await context.close()
    
    async def _detect_cloaking(self, result: SandboxAnalysisResult):
        """Detect cloaking between bot and user analyses."""
        if not result.bot_analysis or not result.user_analysis:
            return
        
        # Compare final URLs
        bot_url = result.bot_analysis.get("final_url", "")
        user_url = result.user_analysis.get("final_url", "")
        
        if bot_url != user_url:
            result.cloaking_detected = True
            result.cloaking_evidence.append(f"Different final URLs: bot={bot_url}, user={user_url}")
        
        # Compare status codes
        bot_status = result.bot_analysis.get("status_code")
        user_status = result.user_analysis.get("status_code")
        
        if bot_status != user_status:
            result.cloaking_detected = True
            result.cloaking_evidence.append(f"Different status codes: bot={bot_status}, user={user_status}")
        
        # Compare page titles
        bot_title = result.bot_analysis.get("metrics", {}).get("title", "")
        user_title = result.user_analysis.get("metrics", {}).get("title", "")
        
        if bot_title != user_title:
            result.cloaking_detected = True
            result.cloaking_evidence.append(f"Different page titles: bot='{bot_title}', user='{user_title}'")
        
        # Compare DOM content (simplified)
        try:
            if "bot" in result.dom_snapshots and "user" in result.dom_snapshots:
                with open(result.dom_snapshots["bot"], 'r', encoding='utf-8') as f:
                    bot_dom = f.read()
                with open(result.dom_snapshots["user"], 'r', encoding='utf-8') as f:
                    user_dom = f.read()
                
                # Simple content length comparison
                if abs(len(bot_dom) - len(user_dom)) > len(bot_dom) * 0.1:  # 10% difference
                    result.cloaking_detected = True
                    result.cloaking_evidence.append(f"Significant DOM size difference: bot={len(bot_dom)}, user={len(user_dom)}")
        
        except Exception as e:
            logger.warning("Failed to compare DOM content", error=str(e))
    
    async def _upload_artifacts(self, result: SandboxAnalysisResult):
        """Upload artifacts to cloud storage using artifact manager."""
        try:
            artifacts = []
            
            # Store screenshots
            for ua_type in ['bot', 'real']:
                screenshot_path = getattr(result, f'{ua_type}_user_screenshot_path', None)
                if screenshot_path and Path(screenshot_path).exists():
                    artifact = await self.artifact_manager.store_screenshot(
                        job_id=self.job_id,
                        file_path=Path(screenshot_path),
                        user_agent_type=ua_type
                    )
                    artifacts.append(artifact)
                    logger.info(f"Stored {ua_type} screenshot", artifact_id=artifact.artifact_id)
            
            # Store DOM snapshots
            for ua_type in ['bot', 'real']:
                dom_path = getattr(result, f'{ua_type}_user_dom_path', None)
                if dom_path and Path(dom_path).exists():
                    artifact = await self.artifact_manager.store_dom_snapshot(
                        job_id=self.job_id,
                        file_path=Path(dom_path),
                        user_agent_type=ua_type
                    )
                    artifacts.append(artifact)
                    logger.info(f"Stored {ua_type} DOM snapshot", artifact_id=artifact.artifact_id)
            
            # Store network logs
            if result.network_logs:
                artifact = await self.artifact_manager.store_logs(
                    job_id=self.job_id,
                    logs_data=result.network_logs,
                    log_type="network_logs"
                )
                artifacts.append(artifact)
                logger.info("Stored network logs", artifact_id=artifact.artifact_id)
            
            # Store console logs
            if result.console_logs:
                artifact = await self.artifact_manager.store_logs(
                    job_id=self.job_id,
                    logs_data=result.console_logs,
                    log_type="console_logs"
                )
                artifacts.append(artifact)
                logger.info("Stored console logs", artifact_id=artifact.artifact_id)
            
            # Store analysis report
            analysis_report = {
                'job_id': self.job_id,
                'target_url': result.target_url,
                'analysis_time': result.analysis_time.isoformat(),
                'cloaking_detected': result.cloaking_detected,
                'security_findings': result.security_findings,
                'bot_user_analysis': result.bot_user_analysis,
                'real_user_analysis': result.real_user_analysis,
                'artifacts': [artifact.to_dict() for artifact in artifacts]
            }
            
            report_artifact = await self.artifact_manager.store_logs(
                job_id=self.job_id,
                logs_data=analysis_report,
                log_type="analysis_report"
            )
            artifacts.append(report_artifact)
            logger.info("Stored analysis report", artifact_id=report_artifact.artifact_id)
            
            # Create archive of all artifacts
            archive_artifact = await self.artifact_manager.create_analysis_archive(
                job_id=self.job_id,
                artifacts=artifacts
            )
            logger.info("Created analysis archive", artifact_id=archive_artifact.artifact_id)
            
            # Update result with artifact information
            result.artifacts = artifacts
            result.archive_artifact_id = archive_artifact.artifact_id
            
            logger.info("Successfully uploaded all artifacts", 
                       job_id=self.job_id, 
                       artifact_count=len(artifacts))
                
        except Exception as e:
            logger.error("Failed to upload artifacts", job_id=self.job_id, error=str(e))
            raise


def setup_signal_handlers():
    """Set up signal handlers for graceful shutdown."""
    def signal_handler(signum, frame):
        logger.info("Received shutdown signal", signal=signum)
        sys.exit(0)
    
    signal.signal(signal.SIGTERM, signal_handler)
    signal.signal(signal.SIGINT, signal_handler)


async def main():
    """Main worker entry point."""
    setup_signal_handlers()
    
    logger.info("Starting sandbox worker", worker_id=os.getenv('WORKER_ID', 'unknown'))
    
    worker = SandboxWorker()
    
    # For testing, analyze a single URL if provided
    test_url = os.getenv('TEST_URL')
    if test_url:
        logger.info("Testing with URL", url=test_url)
        result = await worker.analyze_url(test_url)
        print(json.dumps(result.to_dict(), indent=2))
        return
    
    # Production mode: listen for jobs from queue
    while True:
        try:
            # Check for jobs in Redis queue
            if worker.redis_client:
                job_data = worker.redis_client.brpop('sandbox_jobs', timeout=30)
                if job_data:
                    _, job_json = job_data
                    job = json.loads(job_json)
                    
                    job_id = job.get('job_id')
                    target_url = job.get('url')
                    
                    logger.info("Processing job", job_id=job_id, url=target_url)
                    
                    # Analyze URL
                    result = await worker.analyze_url(target_url, job_id)
                    
                    # Send result back
                    result_json = json.dumps(result.to_dict())
                    worker.redis_client.lpush('sandbox_results', result_json)
                    
                    logger.info("Job completed", job_id=job_id, duration_ms=result.duration_ms)
            
            else:
                # No Redis, sleep and check for environment changes
                await asyncio.sleep(10)
                
        except KeyboardInterrupt:
            logger.info("Worker shutdown requested")
            break
        except Exception as e:
            logger.error("Worker error", error=str(e))
            await asyncio.sleep(5)
    
    logger.info("Sandbox worker stopped")


if __name__ == "__main__":
    asyncio.run(main())
