"""
Browser Worker for Sandboxed Redirect Analysis

Standalone worker process that runs inside a Docker container to perform
secure browser-based redirect analysis with isolation and resource limits.
"""

import asyncio
import json
import logging
import os
import signal
import sys
import time
from typing import Dict, Any, List
import uuid

from browser_redirect_analyzer import BrowserRedirectAnalyzer
from redirect_interfaces import BrowserAnalysisResult, COMMON_USER_AGENTS


# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler('/app/logs/browser_worker.log')
    ]
)
logger = logging.getLogger(__name__)


class BrowserWorker:
    """Sandboxed browser worker for redirect analysis"""
    
    def __init__(self):
        self.analyzer = BrowserRedirectAnalyzer(
            browser_type="chromium",
            headless=True,
            screenshot_dir="/app/screenshots"
        )
        self.running = True
        self.current_analysis = None
        
        # Set up signal handlers for graceful shutdown
        signal.signal(signal.SIGTERM, self._handle_shutdown)
        signal.signal(signal.SIGINT, self._handle_shutdown)
    
    def _handle_shutdown(self, signum, frame):
        """Handle shutdown signals"""
        logger.info(f"Received signal {signum}, shutting down gracefully...")
        self.running = False
        
        if self.current_analysis:
            logger.info("Waiting for current analysis to complete...")
    
    async def run(self):
        """Main worker loop"""
        logger.info("Browser worker starting up...")
        
        # Create necessary directories
        os.makedirs("/app/screenshots", exist_ok=True)
        os.makedirs("/app/logs", exist_ok=True)
        os.makedirs("/app/temp", exist_ok=True)
        
        # Wait for analysis requests
        while self.running:
            try:
                # Check for new analysis requests
                request = await self._get_analysis_request()
                
                if request:
                    self.current_analysis = request
                    result = await self._process_analysis_request(request)
                    await self._send_analysis_result(request['request_id'], result)
                    self.current_analysis = None
                else:
                    # No requests, sleep briefly
                    await asyncio.sleep(1)
                    
            except Exception as e:
                logger.error(f"Error in worker loop: {str(e)}")
                await asyncio.sleep(5)  # Back off on errors
        
        logger.info("Browser worker shutting down")
    
    async def _get_analysis_request(self) -> Dict[str, Any]:
        """Get next analysis request from queue/stdin"""
        # For this implementation, we'll read from stdin
        # In production, this would connect to a message queue
        try:
            # Check if there's input available
            import select
            if select.select([sys.stdin], [], [], 0.1)[0]:
                line = sys.stdin.readline().strip()
                if line:
                    return json.loads(line)
        except Exception as e:
            logger.error(f"Error reading request: {str(e)}")
        
        return None
    
    async def _process_analysis_request(self, request: Dict[str, Any]) -> Dict[str, Any]:
        """Process a single analysis request"""
        request_id = request.get('request_id', str(uuid.uuid4()))
        url = request.get('url')
        user_agents = request.get('user_agents', [
            COMMON_USER_AGENTS["chrome_user"],
            COMMON_USER_AGENTS["chrome_bot"]
        ])
        timeout = request.get('timeout_seconds', 30)
        take_screenshots = request.get('take_screenshots', True)
        
        logger.info(f"Processing analysis request {request_id} for URL: {url}")
        
        start_time = time.time()
        
        try:
            # Validate URL
            if not url or not url.startswith(('http://', 'https://')):
                raise ValueError(f"Invalid URL: {url}")
            
            # Perform browser analysis
            results = await self.analyzer.analyze_with_browser(
                url=url,
                user_agents=user_agents,
                timeout_seconds=min(timeout, 60),  # Cap at 60 seconds
                take_screenshots=take_screenshots,
                capture_network=True
            )
            
            # Convert results to serializable format
            serializable_results = []
            for result in results:
                serializable_result = {
                    'user_agent_used': result.user_agent_used,
                    'final_url': result.final_url,
                    'page_title': result.page_title,
                    'dom_content_hash': result.dom_content_hash,
                    'screenshot_path': result.screenshot_path,
                    'console_logs': result.console_logs,
                    'network_requests': result.network_requests,
                    'javascript_errors': result.javascript_errors,
                    'loaded_scripts': result.loaded_scripts,
                    'forms_detected': result.forms_detected,
                    'execution_time_ms': result.execution_time_ms,
                    'error': result.error
                }
                serializable_results.append(serializable_result)
            
            execution_time = int((time.time() - start_time) * 1000)
            
            return {
                'request_id': request_id,
                'status': 'success',
                'results': serializable_results,
                'execution_time_ms': execution_time,
                'timestamp': time.time()
            }
            
        except Exception as e:
            logger.error(f"Analysis failed for request {request_id}: {str(e)}")
            execution_time = int((time.time() - start_time) * 1000)
            
            return {
                'request_id': request_id,
                'status': 'error',
                'error': str(e),
                'execution_time_ms': execution_time,
                'timestamp': time.time()
            }
    
    async def _send_analysis_result(self, request_id: str, result: Dict[str, Any]):
        """Send analysis result back to caller"""
        # For this implementation, we'll write to stdout
        # In production, this would send to a message queue
        try:
            result_json = json.dumps(result)
            print(result_json, flush=True)
            logger.info(f"Sent result for request {request_id}")
        except Exception as e:
            logger.error(f"Error sending result for request {request_id}: {str(e)}")


class ResourceMonitor:
    """Monitor resource usage and enforce limits"""
    
    def __init__(self, worker: BrowserWorker):
        self.worker = worker
        self.monitoring = True
    
    async def monitor(self):
        """Monitor resource usage"""
        import psutil
        
        process = psutil.Process()
        
        while self.monitoring:
            try:
                # Check memory usage
                memory_info = process.memory_info()
                memory_mb = memory_info.rss / 1024 / 1024
                
                if memory_mb > 512:  # 512MB limit
                    logger.warning(f"High memory usage: {memory_mb:.1f}MB")
                    
                    if memory_mb > 800:  # Hard limit
                        logger.error("Memory limit exceeded, shutting down")
                        self.worker.running = False
                        break
                
                # Check CPU usage
                cpu_percent = process.cpu_percent()
                if cpu_percent > 80:
                    logger.warning(f"High CPU usage: {cpu_percent:.1f}%")
                
                # Check open file descriptors
                num_fds = process.num_fds()
                if num_fds > 100:
                    logger.warning(f"High file descriptor usage: {num_fds}")
                
                await asyncio.sleep(5)  # Check every 5 seconds
                
            except Exception as e:
                logger.error(f"Error in resource monitoring: {str(e)}")
                await asyncio.sleep(10)


async def main():
    """Main entry point"""
    logger.info("Starting PhishNet Browser Worker")
    
    # Create worker
    worker = BrowserWorker()
    
    # Create resource monitor
    monitor = ResourceMonitor(worker)
    
    # Run worker and monitor concurrently
    try:
        await asyncio.gather(
            worker.run(),
            monitor.monitor()
        )
    except KeyboardInterrupt:
        logger.info("Received keyboard interrupt")
    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}")
    finally:
        logger.info("Browser worker stopped")


if __name__ == "__main__":
    # Set process title for monitoring
    try:
        import setproctitle
        setproctitle.setproctitle("phishnet-browser-worker")
    except ImportError:
        pass
    
    # Run the worker
    asyncio.run(main())
