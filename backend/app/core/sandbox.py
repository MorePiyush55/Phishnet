"""
Headless Detonation Sandbox - Safe environment for analyzing suspicious content
Provides isolated execution environment for URLs, attachments, and malicious code
"""

import asyncio
import tempfile
import subprocess
import shutil
import logging
import json
import hashlib
import base64
from typing import Dict, List, Optional, Any, Union
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
from urllib.parse import urlparse
import docker
import playwright
from playwright.async_api import async_playwright, Browser, Page, BrowserContext

logger = logging.getLogger(__name__)

class SandboxType(Enum):
    URL_ANALYSIS = "url_analysis"
    FILE_ANALYSIS = "file_analysis"
    EMAIL_ANALYSIS = "email_analysis"
    DYNAMIC_ANALYSIS = "dynamic_analysis"

# Use centralized ThreatLevel from enums
from src.common.constants import ThreatLevel

@dataclass
class SandboxConfig:
    """Sandbox configuration"""
    timeout_seconds: int = 30
    enable_network: bool = True
    enable_downloads: bool = False
    enable_javascript: bool = True
    enable_images: bool = True
    user_agent: str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    viewport_width: int = 1920
    viewport_height: int = 1080
    screenshot_enabled: bool = True
    har_logging: bool = True
    docker_image: str = "ubuntu:20.04"
    memory_limit: str = "512m"
    cpu_limit: str = "0.5"

@dataclass
class NetworkActivity:
    """Network activity captured during analysis"""
    url: str
    method: str
    status_code: int
    response_size: int
    mime_type: str
    timestamp: datetime
    headers: Dict[str, str] = field(default_factory=dict)

@dataclass
class FileActivity:
    """File system activity"""
    action: str  # create, modify, delete, execute
    path: str
    size: Optional[int] = None
    hash: Optional[str] = None
    timestamp: Optional[datetime] = None

@dataclass
class ProcessActivity:
    """Process activity"""
    pid: int
    name: str
    command: str
    started_at: datetime
    ended_at: Optional[datetime] = None
    exit_code: Optional[int] = None

@dataclass
class SandboxResult:
    """Result of sandbox analysis"""
    sandbox_id: str
    sandbox_type: SandboxType
    target: str  # URL, file path, etc.
    threat_level: ThreatLevel
    confidence: float
    start_time: datetime
    end_time: datetime
    duration_seconds: float
    
    # Analysis results
    screenshot: Optional[bytes] = None
    page_title: Optional[str] = None
    final_url: Optional[str] = None
    redirects: List[str] = field(default_factory=list)
    network_activity: List[NetworkActivity] = field(default_factory=list)
    file_activity: List[FileActivity] = field(default_factory=list)
    process_activity: List[ProcessActivity] = field(default_factory=list)
    
    # Threat indicators
    suspicious_domains: List[str] = field(default_factory=list)
    malicious_ips: List[str] = field(default_factory=list)
    suspicious_files: List[str] = field(default_factory=list)
    javascript_alerts: List[str] = field(default_factory=list)
    form_submissions: List[Dict] = field(default_factory=list)
    
    # Technical details
    console_logs: List[str] = field(default_factory=list)
    error_logs: List[str] = field(default_factory=list)
    performance_metrics: Dict[str, Any] = field(default_factory=dict)
    cookies: List[Dict] = field(default_factory=list)
    local_storage: Dict[str, str] = field(default_factory=dict)
    
    # Metadata
    metadata: Dict[str, Any] = field(default_factory=dict)
    raw_data: Dict[str, Any] = field(default_factory=dict)

class SandboxError(Exception):
    """Sandbox operation error"""
    pass

class HeadlessDetonationSandbox:
    """
    Headless Detonation Sandbox for safe analysis of suspicious content
    
    Features:
    - Browser-based URL analysis with Playwright
    - Docker containerization for isolation
    - Network traffic monitoring
    - Screenshot capture
    - JavaScript execution monitoring
    - File system monitoring
    - Process monitoring
    - Threat intelligence integration
    """
    
    def __init__(self, config: Optional[SandboxConfig] = None):
        self.config = config or SandboxConfig()
        self._sandbox_counter = 0
        self._active_sandboxes: Dict[str, Any] = {}
        self._threat_indicators = self._load_threat_indicators()
        
        # Docker client
        self._docker_client = None
        try:
            self._docker_client = docker.from_env()
        except Exception as e:
            logger.warning(f"Docker not available: {e}")
    
    def _generate_sandbox_id(self) -> str:
        """Generate unique sandbox ID"""
        self._sandbox_counter += 1
        timestamp = int(datetime.utcnow().timestamp())
        return f"sandbox_{self._sandbox_counter:06d}_{timestamp}"
    
    def _load_threat_indicators(self) -> Dict[str, List[str]]:
        """Load threat indicators for analysis"""
        return {
            "malicious_domains": [
                "phishing.example.com",
                "malware-site.net",
                "suspicious-domain.org"
            ],
            "suspicious_keywords": [
                "urgent", "verify", "suspended", "click here",
                "download now", "free money", "congratulations"
            ],
            "malicious_ips": [
                "192.168.1.100",  # Example suspicious IPs
                "10.0.0.50"
            ],
            "suspicious_file_extensions": [
                ".exe", ".scr", ".bat", ".cmd", ".pif", ".com"
            ]
        }
    
    async def analyze_url(self, url: str, config: Optional[SandboxConfig] = None) -> SandboxResult:
        """
        Analyze a URL in the sandbox
        
        Args:
            url: URL to analyze
            config: Optional sandbox configuration override
            
        Returns:
            SandboxResult with analysis findings
        """
        sandbox_config = config or self.config
        sandbox_id = self._generate_sandbox_id()
        start_time = datetime.utcnow()
        
        logger.info(f"Starting URL analysis in sandbox {sandbox_id}: {url}")
        
        try:
            # Create sandbox result
            result = SandboxResult(
                sandbox_id=sandbox_id,
                sandbox_type=SandboxType.URL_ANALYSIS,
                target=url,
                threat_level=ThreatLevel.UNKNOWN,
                confidence=0.0,
                start_time=start_time,
                end_time=start_time,  # Will be updated
                duration_seconds=0.0
            )
            
            # Analyze with Playwright
            await self._analyze_url_with_browser(url, result, sandbox_config)
            
            # Analyze results for threats
            self._analyze_threat_indicators(result)
            
            # Update timing
            end_time = datetime.utcnow()
            result.end_time = end_time
            result.duration_seconds = (end_time - start_time).total_seconds()
            
            logger.info(f"Sandbox {sandbox_id} completed: {result.threat_level.value} "
                       f"(confidence: {result.confidence:.2f})")
            
            return result
            
        except Exception as e:
            logger.error(f"Sandbox {sandbox_id} failed: {e}")
            
            # Return error result
            end_time = datetime.utcnow()
            return SandboxResult(
                sandbox_id=sandbox_id,
                sandbox_type=SandboxType.URL_ANALYSIS,
                target=url,
                threat_level=ThreatLevel.UNKNOWN,
                confidence=0.0,
                start_time=start_time,
                end_time=end_time,
                duration_seconds=(end_time - start_time).total_seconds(),
                error_logs=[str(e)]
            )
    
    async def _analyze_url_with_browser(self, url: str, result: SandboxResult, 
                                       config: SandboxConfig):
        """Analyze URL using Playwright browser"""
        async with async_playwright() as p:
            # Launch browser with security settings
            browser = await p.chromium.launch(
                headless=True,
                args=[
                    '--no-sandbox',
                    '--disable-dev-shm-usage',
                    '--disable-gpu',
                    '--disable-extensions',
                    '--disable-default-apps',
                    '--disable-sync',
                    '--disable-background-timer-throttling',
                    '--disable-renderer-backgrounding',
                    '--disable-backgrounding-occluded-windows'
                ]
            )
            
            try:
                # Create context with settings
                context = await browser.new_context(
                    viewport={'width': config.viewport_width, 'height': config.viewport_height},
                    user_agent=config.user_agent,
                    java_script_enabled=config.enable_javascript,
                    accept_downloads=config.enable_downloads,
                    ignore_https_errors=True
                )
                
                # Create page
                page = await context.new_page()
                
                # Set up monitoring
                await self._setup_page_monitoring(page, result)
                
                # Navigate to URL with timeout
                try:
                    response = await page.goto(
                        url,
                        timeout=config.timeout_seconds * 1000,
                        wait_until='domcontentloaded'
                    )
                    
                    if response:
                        result.network_activity.append(NetworkActivity(
                            url=response.url,
                            method="GET",
                            status_code=response.status,
                            response_size=len(await response.body()) if response else 0,
                            mime_type=response.headers.get('content-type', ''),
                            timestamp=datetime.utcnow(),
                            headers=dict(response.headers)
                        ))
                        
                        result.final_url = response.url
                
                except Exception as e:
                    result.error_logs.append(f"Navigation failed: {e}")
                    return
                
                # Wait for page to load
                await asyncio.sleep(2)
                
                # Capture page information
                result.page_title = await page.title()
                result.final_url = page.url
                
                # Capture screenshot
                if config.screenshot_enabled:
                    try:
                        screenshot_bytes = await page.screenshot(
                            full_page=True,
                            type='png'
                        )
                        result.screenshot = screenshot_bytes
                    except Exception as e:
                        result.error_logs.append(f"Screenshot failed: {e}")
                
                # Capture cookies
                cookies = await context.cookies()
                result.cookies = [
                    {
                        'name': cookie['name'],
                        'value': cookie['value'],
                        'domain': cookie['domain'],
                        'path': cookie['path']
                    }
                    for cookie in cookies
                ]
                
                # Capture local storage
                try:
                    local_storage = await page.evaluate("""
                        () => {
                            const storage = {};
                            for (let i = 0; i < localStorage.length; i++) {
                                const key = localStorage.key(i);
                                storage[key] = localStorage.getItem(key);
                            }
                            return storage;
                        }
                    """)
                    result.local_storage = local_storage
                except Exception as e:
                    result.error_logs.append(f"Local storage capture failed: {e}")
                
                # Check for suspicious JavaScript
                await self._check_javascript_behavior(page, result)
                
                # Monitor for additional network requests
                await asyncio.sleep(3)
                
            finally:
                await browser.close()
    
    async def _setup_page_monitoring(self, page: Page, result: SandboxResult):
        """Set up page monitoring for threats"""
        
        # Monitor console logs
        page.on('console', lambda msg: result.console_logs.append(
            f"[{msg.type}] {msg.text}"
        ))
        
        # Monitor JavaScript errors
        page.on('pageerror', lambda error: result.error_logs.append(str(error)))
        
        # Monitor network requests
        page.on('request', lambda request: self._on_request(request, result))
        page.on('response', lambda response: self._on_response(response, result))
        
        # Monitor dialog boxes (alerts, confirms, etc.)
        page.on('dialog', lambda dialog: self._on_dialog(dialog, result))
    
    def _on_request(self, request, result: SandboxResult):
        """Handle network request"""
        try:
            # Check for suspicious domains
            parsed_url = urlparse(request.url)
            domain = parsed_url.netloc.lower()
            
            if domain in self._threat_indicators['malicious_domains']:
                result.suspicious_domains.append(domain)
            
            # Log request
            logger.debug(f"Request: {request.method} {request.url}")
            
        except Exception as e:
            result.error_logs.append(f"Request monitoring error: {e}")
    
    def _on_response(self, response, result: SandboxResult):
        """Handle network response"""
        try:
            # Track redirects
            if response.status in [301, 302, 303, 307, 308]:
                if response.url not in result.redirects:
                    result.redirects.append(response.url)
            
            # Monitor for suspicious content types
            content_type = response.headers.get('content-type', '').lower()
            if any(ext in content_type for ext in ['application/octet-stream', 'application/x-msdownload']):
                result.suspicious_files.append(response.url)
            
        except Exception as e:
            result.error_logs.append(f"Response monitoring error: {e}")
    
    def _on_dialog(self, dialog, result: SandboxResult):
        """Handle JavaScript dialogs"""
        try:
            result.javascript_alerts.append(f"{dialog.type}: {dialog.message}")
            dialog.dismiss()  # Automatically dismiss dialogs
        except Exception as e:
            result.error_logs.append(f"Dialog handling error: {e}")
    
    async def _check_javascript_behavior(self, page: Page, result: SandboxResult):
        """Check for suspicious JavaScript behavior"""
        try:
            # Check for form auto-submission
            forms = await page.query_selector_all('form')
            for form in forms:
                action = await form.get_attribute('action')
                method = await form.get_attribute('method') or 'GET'
                
                if action:
                    result.form_submissions.append({
                        'action': action,
                        'method': method.upper(),
                        'timestamp': datetime.utcnow().isoformat()
                    })
            
            # Check for suspicious JavaScript patterns
            js_patterns = [
                'eval(',
                'document.write(',
                'window.open(',
                'location.href=',
                'document.cookie'
            ]
            
            page_content = await page.content()
            for pattern in js_patterns:
                if pattern in page_content:
                    result.console_logs.append(f"Suspicious JS pattern detected: {pattern}")
                    
        except Exception as e:
            result.error_logs.append(f"JavaScript analysis error: {e}")
    
    def _analyze_threat_indicators(self, result: SandboxResult):
        """Analyze results for threat indicators"""
        threat_score = 0.0
        max_score = 100.0
        
        # Check suspicious domains
        if result.suspicious_domains:
            threat_score += 40.0
            logger.warning(f"Suspicious domains detected: {result.suspicious_domains}")
        
        # Check for redirects (multiple redirects can be suspicious)
        if len(result.redirects) > 3:
            threat_score += 20.0
        
        # Check for JavaScript alerts (common in phishing)
        if result.javascript_alerts:
            threat_score += 15.0
        
        # Check for suspicious files
        if result.suspicious_files:
            threat_score += 25.0
        
        # Check for form submissions to external domains
        for form in result.form_submissions:
            parsed_action = urlparse(form['action'])
            parsed_target = urlparse(result.target)
            
            if (parsed_action.netloc and 
                parsed_action.netloc != parsed_target.netloc):
                threat_score += 20.0
        
        # Check console errors (might indicate exploitation attempts)
        error_count = len([log for log in result.console_logs if '[error]' in log.lower()])
        if error_count > 5:
            threat_score += 10.0
        
        # Calculate confidence and threat level
        confidence = min(threat_score / max_score, 1.0)
        result.confidence = confidence
        
        if threat_score >= 60:
            result.threat_level = ThreatLevel.MALICIOUS
        elif threat_score >= 30:
            result.threat_level = ThreatLevel.SUSPICIOUS
        elif threat_score <= 10:
            result.threat_level = ThreatLevel.SAFE
        else:
            result.threat_level = ThreatLevel.UNKNOWN
        
        # Store analysis metadata
        result.metadata.update({
            'threat_score': threat_score,
            'max_possible_score': max_score,
            'indicators_detected': {
                'suspicious_domains': len(result.suspicious_domains),
                'redirects': len(result.redirects),
                'javascript_alerts': len(result.javascript_alerts),
                'suspicious_files': len(result.suspicious_files),
                'external_forms': len([f for f in result.form_submissions 
                                     if urlparse(f['action']).netloc]),
                'console_errors': error_count
            }
        })
    
    async def analyze_file(self, file_path: str, config: Optional[SandboxConfig] = None) -> SandboxResult:
        """
        Analyze a file in the sandbox
        
        Args:
            file_path: Path to file to analyze
            config: Optional sandbox configuration override
            
        Returns:
            SandboxResult with analysis findings
        """
        sandbox_config = config or self.config
        sandbox_id = self._generate_sandbox_id()
        start_time = datetime.utcnow()
        
        logger.info(f"Starting file analysis in sandbox {sandbox_id}: {file_path}")
        
        # Create result
        result = SandboxResult(
            sandbox_id=sandbox_id,
            sandbox_type=SandboxType.FILE_ANALYSIS,
            target=file_path,
            threat_level=ThreatLevel.UNKNOWN,
            confidence=0.0,
            start_time=start_time,
            end_time=start_time,
            duration_seconds=0.0
        )
        
        try:
            # Analyze file properties
            file_path_obj = Path(file_path)
            if not file_path_obj.exists():
                raise SandboxError(f"File not found: {file_path}")
            
            # Get file hash
            with open(file_path, 'rb') as f:
                file_content = f.read()
                file_hash = hashlib.sha256(file_content).hexdigest()
            
            result.metadata['file_size'] = len(file_content)
            result.metadata['file_hash'] = file_hash
            result.metadata['file_extension'] = file_path_obj.suffix.lower()
            
            # Check for suspicious file extensions
            if result.metadata['file_extension'] in self._threat_indicators['suspicious_file_extensions']:
                result.suspicious_files.append(file_path)
            
            # Analyze file content for threats
            await self._analyze_file_content(file_content, result)
            
            # Determine threat level
            self._analyze_threat_indicators(result)
            
            # Update timing
            end_time = datetime.utcnow()
            result.end_time = end_time
            result.duration_seconds = (end_time - start_time).total_seconds()
            
            return result
            
        except Exception as e:
            logger.error(f"File analysis failed: {e}")
            result.error_logs.append(str(e))
            
            end_time = datetime.utcnow()
            result.end_time = end_time
            result.duration_seconds = (end_time - start_time).total_seconds()
            
            return result
    
    async def _analyze_file_content(self, content: bytes, result: SandboxResult):
        """Analyze file content for threats"""
        try:
            # Convert to string for text analysis
            try:
                text_content = content.decode('utf-8', errors='ignore')
            except:
                text_content = str(content)
            
            # Check for suspicious keywords
            suspicious_count = 0
            for keyword in self._threat_indicators['suspicious_keywords']:
                if keyword.lower() in text_content.lower():
                    suspicious_count += 1
                    result.console_logs.append(f"Suspicious keyword detected: {keyword}")
            
            result.metadata['suspicious_keywords_count'] = suspicious_count
            
            # Check for URLs in file content
            import re
            url_pattern = r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
            urls = re.findall(url_pattern, text_content)
            
            for url in urls:
                parsed_url = urlparse(url)
                domain = parsed_url.netloc.lower()
                
                if domain in self._threat_indicators['malicious_domains']:
                    result.suspicious_domains.append(domain)
            
            result.metadata['embedded_urls'] = urls
            
        except Exception as e:
            result.error_logs.append(f"File content analysis error: {e}")
    
    def get_sandbox_summary(self) -> Dict[str, Any]:
        """Get summary of sandbox operations"""
        return {
            "total_analyses": self._sandbox_counter,
            "active_sandboxes": len(self._active_sandboxes),
            "threat_indicators_loaded": len(self._threat_indicators),
            "docker_available": self._docker_client is not None
        }

# Convenience functions
async def quick_url_analysis(url: str, timeout: int = 30) -> SandboxResult:
    """Quick URL analysis with default settings"""
    config = SandboxConfig(timeout_seconds=timeout)
    sandbox = HeadlessDetonationSandbox(config)
    return await sandbox.analyze_url(url)

async def analyze_suspicious_email_links(email_content: str) -> List[SandboxResult]:
    """Analyze all URLs found in email content"""
    import re
    
    # Extract URLs from email
    url_pattern = r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
    urls = re.findall(url_pattern, email_content)
    
    if not urls:
        return []
    
    # Analyze each URL
    sandbox = HeadlessDetonationSandbox()
    results = []
    
    for url in urls[:5]:  # Limit to first 5 URLs to avoid overload
        try:
            result = await sandbox.analyze_url(url)
            results.append(result)
        except Exception as e:
            logger.error(f"Failed to analyze URL {url}: {e}")
    
    return results

# Example usage
async def example_usage():
    """Example of using the detonation sandbox"""
    
    # Create sandbox
    config = SandboxConfig(
        timeout_seconds=20,
        screenshot_enabled=True,
        enable_downloads=False
    )
    
    sandbox = HeadlessDetonationSandbox(config)
    
    # Analyze suspicious URL
    test_url = "https://example.com"
    result = await sandbox.analyze_url(test_url)
    
    print(f"Analysis Results for {test_url}:")
    print(f"  Threat Level: {result.threat_level.value}")
    print(f"  Confidence: {result.confidence:.2f}")
    print(f"  Duration: {result.duration_seconds:.2f}s")
    print(f"  Final URL: {result.final_url}")
    print(f"  Redirects: {len(result.redirects)}")
    print(f"  Network Requests: {len(result.network_activity)}")
    
    if result.suspicious_domains:
        print(f"  Suspicious Domains: {result.suspicious_domains}")
    
    if result.screenshot:
        print(f"  Screenshot captured: {len(result.screenshot)} bytes")

# Example usage is now available via CLI: python phishnet-cli.py demo sandbox
