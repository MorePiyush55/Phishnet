"""
Secure Sandbox Executor for PhishNet

Executes suspicious links and attachments in isolated environment
with evidence collection and security monitoring.
"""

import os
import sys
import json
import asyncio
import hashlib
import time
import signal
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, asdict
from contextlib import asynccontextmanager

import structlog
from playwright.async_api import async_playwright, Browser, BrowserContext, Page
import psutil
import httpx
from PIL import Image
import mss

# Configure structured logging
structlog.configure(
    processors=[
        structlog.stdlib.filter_by_level,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.TimeStamper(fmt="iso"),
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


@dataclass
class SandboxConfig:
    """Sandbox execution configuration."""
    session_id: str
    execution_timeout: int = 60
    screenshot_enabled: bool = True
    network_monitoring: bool = True
    evidence_collection: bool = True
    proxy_url: Optional[str] = None
    workdir: Path = Path("/sandbox/workdir")
    evidence_dir: Path = Path("/sandbox/evidence")
    logs_dir: Path = Path("/sandbox/logs")
    temp_dir: Path = Path("/sandbox/temp")


@dataclass
class NetworkCapture:
    """Network traffic capture data."""
    timestamp: datetime
    source_ip: str
    dest_ip: str
    dest_port: int
    protocol: str
    payload_size: int
    domain: Optional[str] = None
    url: Optional[str] = None
    headers: Dict[str, str] = None
    response_code: Optional[int] = None


@dataclass
class ScreenshotEvidence:
    """Screenshot evidence data."""
    timestamp: datetime
    filename: str
    width: int
    height: int
    format: str
    file_size: int
    sha256_hash: str
    page_url: str
    page_title: str


@dataclass
class DOMEvidence:
    """DOM dump evidence data."""
    timestamp: datetime
    filename: str
    file_size: int
    sha256_hash: str
    page_url: str
    elements_count: int
    scripts_count: int
    forms_count: int
    external_resources: List[str]


@dataclass
class SandboxEvidence:
    """Complete sandbox execution evidence."""
    session_id: str
    start_time: datetime
    end_time: datetime
    target_url: str
    execution_status: str
    screenshots: List[ScreenshotEvidence]
    dom_dumps: List[DOMEvidence]
    network_captures: List[NetworkCapture]
    process_info: Dict[str, Any]
    security_events: List[Dict[str, Any]]
    final_url: str
    page_title: str
    content_hash: str
    threat_indicators: List[str]


class NetworkMonitor:
    """Monitor network traffic during sandbox execution."""
    
    def __init__(self, config: SandboxConfig):
        self.config = config
        self.captures: List[NetworkCapture] = []
        self.monitoring = False
        self.process: Optional[subprocess.Popen] = None
    
    async def start_monitoring(self):
        """Start network traffic monitoring."""
        if not self.config.network_monitoring:
            return
        
        try:
            # Use tcpdump for packet capture
            capture_file = self.config.temp_dir / f"network_{self.config.session_id}.pcap"
            
            self.process = subprocess.Popen([
                "tcpdump", 
                "-i", "eth0",
                "-w", str(capture_file),
                "-s", "1518",  # Capture full packets
                "not host 127.0.0.1"  # Exclude localhost
            ], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            
            self.monitoring = True
            logger.info("Network monitoring started", capture_file=str(capture_file))
            
        except Exception as e:
            logger.error("Failed to start network monitoring", error=str(e))
    
    async def stop_monitoring(self):
        """Stop network traffic monitoring."""
        if self.process and self.monitoring:
            try:
                self.process.terminate()
                await asyncio.sleep(1)
                if self.process.poll() is None:
                    self.process.kill()
                
                self.monitoring = False
                logger.info("Network monitoring stopped")
                
            except Exception as e:
                logger.error("Error stopping network monitoring", error=str(e))
    
    async def parse_captures(self) -> List[NetworkCapture]:
        """Parse captured network traffic."""
        captures = []
        capture_file = self.config.temp_dir / f"network_{self.config.session_id}.pcap"
        
        if not capture_file.exists():
            return captures
        
        try:
            # Parse with tshark if available, otherwise basic analysis
            result = subprocess.run([
                "tshark", "-r", str(capture_file), 
                "-T", "json", "-e", "frame.time", "-e", "ip.src", "-e", "ip.dst",
                "-e", "tcp.dstport", "-e", "http.host", "-e", "http.request.uri"
            ], capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0:
                for line in result.stdout.strip().split('\n'):
                    if line:
                        data = json.loads(line)
                        capture = self._parse_packet_data(data)
                        if capture:
                            captures.append(capture)
            
        except Exception as e:
            logger.warning("Error parsing network captures", error=str(e))
        
        return captures
    
    def _parse_packet_data(self, data: Dict) -> Optional[NetworkCapture]:
        """Parse individual packet data."""
        try:
            return NetworkCapture(
                timestamp=datetime.now(timezone.utc),
                source_ip=data.get("ip.src", "unknown"),
                dest_ip=data.get("ip.dst", "unknown"),
                dest_port=int(data.get("tcp.dstport", 0)),
                protocol="TCP",
                payload_size=0,
                domain=data.get("http.host"),
                url=data.get("http.request.uri")
            )
        except Exception:
            return None


class SecurityMonitor:
    """Monitor security events during sandbox execution."""
    
    def __init__(self, config: SandboxConfig):
        self.config = config
        self.events: List[Dict[str, Any]] = []
        self.monitoring = False
    
    async def start_monitoring(self):
        """Start security monitoring."""
        self.monitoring = True
        logger.info("Security monitoring started")
        
        # Monitor for suspicious activities
        asyncio.create_task(self._monitor_processes())
        asyncio.create_task(self._monitor_file_system())
    
    async def stop_monitoring(self):
        """Stop security monitoring."""
        self.monitoring = False
        logger.info("Security monitoring stopped")
    
    async def _monitor_processes(self):
        """Monitor process creation and behavior."""
        while self.monitoring:
            try:
                processes = list(psutil.process_iter(['pid', 'name', 'cmdline', 'cpu_percent']))
                
                for proc in processes:
                    try:
                        info = proc.info
                        if info['cpu_percent'] > 80:  # High CPU usage
                            self._add_security_event("high_cpu_usage", {
                                "process": info['name'],
                                "pid": info['pid'],
                                "cpu_percent": info['cpu_percent']
                            })
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass
                
                await asyncio.sleep(5)
                
            except Exception as e:
                logger.warning("Process monitoring error", error=str(e))
                await asyncio.sleep(5)
    
    async def _monitor_file_system(self):
        """Monitor file system activities."""
        while self.monitoring:
            try:
                # Check for suspicious file modifications
                temp_files = list(self.config.temp_dir.glob("*"))
                
                for file_path in temp_files:
                    if file_path.is_file() and file_path.stat().st_size > 50 * 1024 * 1024:  # > 50MB
                        self._add_security_event("large_file_created", {
                            "file": str(file_path),
                            "size": file_path.stat().st_size
                        })
                
                await asyncio.sleep(10)
                
            except Exception as e:
                logger.warning("File system monitoring error", error=str(e))
                await asyncio.sleep(10)
    
    def _add_security_event(self, event_type: str, data: Dict[str, Any]):
        """Add security event."""
        self.events.append({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "type": event_type,
            "data": data
        })


class SandboxExecutor:
    """Main sandbox executor for safe content analysis."""
    
    def __init__(self, config: SandboxConfig):
        self.config = config
        self.network_monitor = NetworkMonitor(config)
        self.security_monitor = SecurityMonitor(config)
        self.browser: Optional[Browser] = None
        self.execution_start: Optional[datetime] = None
        self.evidence: Optional[SandboxEvidence] = None
    
    async def setup_environment(self):
        """Setup secure sandbox environment."""
        try:
            # Create required directories
            for directory in [self.config.workdir, self.config.evidence_dir, 
                            self.config.logs_dir, self.config.temp_dir]:
                directory.mkdir(parents=True, exist_ok=True)
            
            # Set environment security
            os.environ["CHROME_NO_SANDBOX"] = "true"
            os.environ["DISPLAY"] = ":99"
            
            # Setup signal handlers for cleanup
            signal.signal(signal.SIGTERM, self._signal_handler)
            signal.signal(signal.SIGINT, self._signal_handler)
            
            logger.info("Sandbox environment setup complete", session_id=self.config.session_id)
            
        except Exception as e:
            logger.error("Failed to setup sandbox environment", error=str(e))
            raise
    
    def _signal_handler(self, signum, frame):
        """Handle shutdown signals."""
        logger.info("Received shutdown signal", signal=signum)
        asyncio.create_task(self.cleanup())
    
    async def execute_url(self, target_url: str) -> SandboxEvidence:
        """Execute URL analysis in sandbox."""
        self.execution_start = datetime.now(timezone.utc)
        
        try:
            logger.info("Starting URL execution", 
                       session_id=self.config.session_id, 
                       target_url=target_url)
            
            # Start monitoring
            await self.network_monitor.start_monitoring()
            await self.security_monitor.start_monitoring()
            
            # Execute with timeout
            evidence = await asyncio.wait_for(
                self._execute_url_internal(target_url),
                timeout=self.config.execution_timeout
            )
            
            return evidence
            
        except asyncio.TimeoutError:
            logger.warning("URL execution timed out", 
                          session_id=self.config.session_id,
                          timeout=self.config.execution_timeout)
            
            return await self._create_timeout_evidence(target_url)
            
        except Exception as e:
            logger.error("URL execution failed", 
                        session_id=self.config.session_id,
                        error=str(e))
            
            return await self._create_error_evidence(target_url, str(e))
            
        finally:
            await self.cleanup()
    
    async def _execute_url_internal(self, target_url: str) -> SandboxEvidence:
        """Internal URL execution with evidence collection."""
        screenshots = []
        dom_dumps = []
        
        async with async_playwright() as playwright:
            # Launch browser with security flags
            self.browser = await playwright.chromium.launch(
                headless=True,
                args=[
                    "--no-sandbox",
                    "--disable-setuid-sandbox",
                    "--disable-dev-shm-usage",
                    "--disable-background-timer-throttling",
                    "--disable-renderer-backgrounding",
                    "--disable-backgrounding-occluded-windows",
                    "--disable-features=TranslateUI",
                    "--disable-ipc-flooding-protection",
                    "--disable-default-apps",
                    "--disable-extensions",
                    "--disable-plugins",
                    "--disable-web-security",  # For analysis purposes
                    "--disable-features=VizDisplayCompositor",
                    "--user-agent=Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
                ]
            )
            
            # Create isolated context
            context = await self.browser.new_context(
                viewport={"width": 1920, "height": 1080},
                ignore_https_errors=True,
                java_script_enabled=True,
                accept_downloads=False,
                bypass_csp=True,  # For analysis
                extra_http_headers={
                    "Accept-Language": "en-US,en;q=0.9"
                }
            )
            
            page = await context.new_page()
            
            try:
                # Navigate to target URL
                logger.info("Navigating to target URL", url=target_url)
                response = await page.goto(target_url, wait_until="domcontentloaded", timeout=30000)
                
                # Wait for page to stabilize
                await asyncio.sleep(2)
                
                # Take initial screenshot
                if self.config.screenshot_enabled:
                    screenshot = await self._capture_screenshot(page, "initial")
                    if screenshot:
                        screenshots.append(screenshot)
                
                # Capture DOM
                dom_dump = await self._capture_dom(page, "initial")
                if dom_dump:
                    dom_dumps.append(dom_dump)
                
                # Interact with page (scroll, click, etc.)
                await self._interact_with_page(page)
                
                # Take final screenshot
                if self.config.screenshot_enabled:
                    screenshot = await self._capture_screenshot(page, "final")
                    if screenshot:
                        screenshots.append(screenshot)
                
                # Final DOM capture
                dom_dump = await self._capture_dom(page, "final")
                if dom_dump:
                    dom_dumps.append(dom_dump)
                
                # Get final page information
                final_url = page.url
                page_title = await page.title()
                content = await page.content()
                content_hash = hashlib.sha256(content.encode()).hexdigest()
                
                # Analyze for threat indicators
                threat_indicators = await self._analyze_threats(page, content)
                
            except Exception as e:
                logger.error("Page execution error", error=str(e))
                final_url = target_url
                page_title = "Error"
                content_hash = "error"
                threat_indicators = [f"execution_error: {str(e)}"]
            
            finally:
                await context.close()
        
        # Stop monitoring and collect evidence
        await self.network_monitor.stop_monitoring()
        await self.security_monitor.stop_monitoring()
        
        network_captures = await self.network_monitor.parse_captures()
        
        # Create evidence record
        evidence = SandboxEvidence(
            session_id=self.config.session_id,
            start_time=self.execution_start,
            end_time=datetime.now(timezone.utc),
            target_url=target_url,
            execution_status="completed",
            screenshots=screenshots,
            dom_dumps=dom_dumps,
            network_captures=network_captures,
            process_info=self._get_process_info(),
            security_events=self.security_monitor.events,
            final_url=final_url,
            page_title=page_title,
            content_hash=content_hash,
            threat_indicators=threat_indicators
        )
        
        # Save evidence
        await self._save_evidence(evidence)
        
        return evidence
    
    async def _capture_screenshot(self, page: Page, stage: str) -> Optional[ScreenshotEvidence]:
        """Capture screenshot evidence."""
        try:
            timestamp = datetime.now(timezone.utc)
            filename = f"screenshot_{self.config.session_id}_{stage}_{int(timestamp.timestamp())}.png"
            filepath = self.config.evidence_dir / filename
            
            screenshot_bytes = await page.screenshot(
                path=str(filepath),
                full_page=True,
                type="png"
            )
            
            # Get image metadata
            with Image.open(filepath) as img:
                width, height = img.size
                file_size = filepath.stat().st_size
                sha256_hash = hashlib.sha256(screenshot_bytes).hexdigest()
            
            return ScreenshotEvidence(
                timestamp=timestamp,
                filename=filename,
                width=width,
                height=height,
                format="png",
                file_size=file_size,
                sha256_hash=sha256_hash,
                page_url=page.url,
                page_title=await page.title()
            )
            
        except Exception as e:
            logger.error("Screenshot capture failed", error=str(e))
            return None
    
    async def _capture_dom(self, page: Page, stage: str) -> Optional[DOMEvidence]:
        """Capture DOM dump evidence."""
        try:
            timestamp = datetime.now(timezone.utc)
            filename = f"dom_{self.config.session_id}_{stage}_{int(timestamp.timestamp())}.html"
            filepath = self.config.evidence_dir / filename
            
            content = await page.content()
            
            # Write DOM content
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(content)
            
            # Analyze DOM
            elements_count = await page.evaluate("document.querySelectorAll('*').length")
            scripts_count = await page.evaluate("document.querySelectorAll('script').length")
            forms_count = await page.evaluate("document.querySelectorAll('form').length")
            
            # Extract external resources
            external_resources = await page.evaluate("""
                Array.from(document.querySelectorAll('img, script, link, iframe')).map(el => {
                    return el.src || el.href || '';
                }).filter(url => url && !url.startsWith(window.location.origin));
            """)
            
            file_size = filepath.stat().st_size
            sha256_hash = hashlib.sha256(content.encode()).hexdigest()
            
            return DOMEvidence(
                timestamp=timestamp,
                filename=filename,
                file_size=file_size,
                sha256_hash=sha256_hash,
                page_url=page.url,
                elements_count=elements_count,
                scripts_count=scripts_count,
                forms_count=forms_count,
                external_resources=external_resources
            )
            
        except Exception as e:
            logger.error("DOM capture failed", error=str(e))
            return None
    
    async def _interact_with_page(self, page: Page):
        """Perform safe interactions with the page."""
        try:
            # Scroll through page
            await page.evaluate("window.scrollTo(0, document.body.scrollHeight / 2)")
            await asyncio.sleep(1)
            
            await page.evaluate("window.scrollTo(0, document.body.scrollHeight)")
            await asyncio.sleep(1)
            
            await page.evaluate("window.scrollTo(0, 0)")
            await asyncio.sleep(1)
            
            # Look for common interactive elements (but don't click)
            buttons = await page.query_selector_all("button, input[type='submit']")
            links = await page.query_selector_all("a[href]")
            
            logger.info("Page interaction completed", 
                       buttons_found=len(buttons),
                       links_found=len(links))
            
        except Exception as e:
            logger.warning("Page interaction error", error=str(e))
    
    async def _analyze_threats(self, page: Page, content: str) -> List[str]:
        """Analyze page for threat indicators."""
        threats = []
        
        try:
            # Check for suspicious JavaScript
            scripts = await page.evaluate("""
                Array.from(document.querySelectorAll('script')).map(script => script.innerHTML);
            """)
            
            for script in scripts:
                if any(keyword in script.lower() for keyword in ['eval(', 'document.write(', 'unescape(', 'fromcharcode(']):
                    threats.append("suspicious_javascript")
                    break
            
            # Check for forms (potential phishing)
            forms = await page.query_selector_all("form")
            if forms:
                for form in forms:
                    action = await form.get_attribute("action")
                    if action and not action.startswith(page.url):
                        threats.append("external_form_submission")
                        break
            
            # Check for suspicious URLs in content
            if any(keyword in content.lower() for keyword in ['paypal', 'amazon', 'microsoft', 'google', 'apple']):
                threats.append("brand_impersonation_indicators")
            
            # Check for obfuscated content
            if content.count('%') > 50 or content.count('\\x') > 20:
                threats.append("obfuscated_content")
            
        except Exception as e:
            logger.warning("Threat analysis error", error=str(e))
            threats.append(f"analysis_error: {str(e)}")
        
        return threats
    
    def _get_process_info(self) -> Dict[str, Any]:
        """Get current process information."""
        try:
            process = psutil.Process()
            return {
                "pid": process.pid,
                "memory_info": process.memory_info()._asdict(),
                "cpu_percent": process.cpu_percent(),
                "num_threads": process.num_threads(),
                "create_time": process.create_time()
            }
        except Exception:
            return {}
    
    async def _save_evidence(self, evidence: SandboxEvidence):
        """Save evidence to disk."""
        try:
            evidence_file = self.config.evidence_dir / f"evidence_{self.config.session_id}.json"
            
            # Convert to serializable format
            evidence_dict = asdict(evidence)
            
            # Handle datetime serialization
            def datetime_serializer(obj):
                if isinstance(obj, datetime):
                    return obj.isoformat()
                raise TypeError(f"Object of type {type(obj)} is not JSON serializable")
            
            with open(evidence_file, 'w') as f:
                json.dump(evidence_dict, f, default=datetime_serializer, indent=2)
            
            logger.info("Evidence saved", evidence_file=str(evidence_file))
            
        except Exception as e:
            logger.error("Failed to save evidence", error=str(e))
    
    async def _create_timeout_evidence(self, target_url: str) -> SandboxEvidence:
        """Create evidence for timeout scenario."""
        return SandboxEvidence(
            session_id=self.config.session_id,
            start_time=self.execution_start,
            end_time=datetime.now(timezone.utc),
            target_url=target_url,
            execution_status="timeout",
            screenshots=[],
            dom_dumps=[],
            network_captures=[],
            process_info=self._get_process_info(),
            security_events=self.security_monitor.events,
            final_url=target_url,
            page_title="Execution Timeout",
            content_hash="timeout",
            threat_indicators=["execution_timeout"]
        )
    
    async def _create_error_evidence(self, target_url: str, error: str) -> SandboxEvidence:
        """Create evidence for error scenario."""
        return SandboxEvidence(
            session_id=self.config.session_id,
            start_time=self.execution_start,
            end_time=datetime.now(timezone.utc),
            target_url=target_url,
            execution_status="error",
            screenshots=[],
            dom_dumps=[],
            network_captures=[],
            process_info=self._get_process_info(),
            security_events=self.security_monitor.events,
            final_url=target_url,
            page_title="Execution Error",
            content_hash="error",
            threat_indicators=[f"execution_error: {error}"]
        )
    
    async def cleanup(self):
        """Cleanup sandbox resources."""
        try:
            logger.info("Starting sandbox cleanup", session_id=self.config.session_id)
            
            # Stop monitoring
            await self.network_monitor.stop_monitoring()
            await self.security_monitor.stop_monitoring()
            
            # Close browser
            if self.browser:
                await self.browser.close()
            
            # Clean temporary files
            for temp_file in self.config.temp_dir.glob("*"):
                try:
                    if temp_file.is_file():
                        temp_file.unlink()
                    elif temp_file.is_dir():
                        import shutil
                        shutil.rmtree(temp_file)
                except Exception as e:
                    logger.warning("Failed to clean temp file", file=str(temp_file), error=str(e))
            
            logger.info("Sandbox cleanup completed", session_id=self.config.session_id)
            
        except Exception as e:
            logger.error("Sandbox cleanup error", error=str(e))


async def main():
    """Main sandbox execution entry point."""
    try:
        # Get configuration from environment
        session_id = os.environ.get("SANDBOX_SESSION_ID", f"sandbox_{int(time.time())}")
        execution_timeout = int(os.environ.get("EXECUTION_TIMEOUT", "60"))
        target_url = os.environ.get("TARGET_URL")
        
        if not target_url:
            logger.error("TARGET_URL environment variable required")
            sys.exit(1)
        
        # Create configuration
        config = SandboxConfig(
            session_id=session_id,
            execution_timeout=execution_timeout,
            screenshot_enabled=os.environ.get("SCREENSHOT_ENABLED", "true").lower() == "true",
            network_monitoring=os.environ.get("NETWORK_MONITORING", "true").lower() == "true",
            evidence_collection=os.environ.get("EVIDENCE_COLLECTION", "true").lower() == "true",
            proxy_url=os.environ.get("SANDBOX_PROXY_URL")
        )
        
        # Create and setup executor
        executor = SandboxExecutor(config)
        await executor.setup_environment()
        
        # Execute URL analysis
        evidence = await executor.execute_url(target_url)
        
        logger.info("Sandbox execution completed successfully", 
                   session_id=session_id,
                   execution_status=evidence.execution_status,
                   threat_indicators_count=len(evidence.threat_indicators))
        
        # Exit with appropriate code
        if evidence.execution_status == "completed":
            sys.exit(0)
        elif evidence.execution_status == "timeout":
            sys.exit(2)
        else:
            sys.exit(1)
        
    except Exception as e:
        logger.error("Sandbox execution failed", error=str(e))
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())