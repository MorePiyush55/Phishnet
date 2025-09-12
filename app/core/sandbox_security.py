"""
Sandbox IP Control and Network Security
Ensures all external scans originate from controlled sandbox IPs.
"""

import ipaddress
import socket
import logging
import asyncio
import aiohttp
from typing import List, Dict, Optional, Any, Set
from dataclasses import dataclass
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from app.core.config import get_settings
from app.core.redis_client import get_redis_client

logger = logging.getLogger(__name__)

@dataclass
class SandboxNetwork:
    """Configuration for sandbox network"""
    name: str
    ip_ranges: List[str]
    interface: Optional[str] = None
    proxy_url: Optional[str] = None
    vpn_endpoint: Optional[str] = None
    is_active: bool = True

class SandboxIPManager:
    """
    Manages sandbox IP addresses and ensures all external scans
    originate from controlled IPs, never from user devices.
    """
    
    def __init__(self):
        self.settings = get_settings()
        self.redis_client = get_redis_client()
        
        # Configure sandbox networks
        self.sandbox_networks = self._load_sandbox_networks()
        self.current_network = None
        self.blocked_user_ips = set()
        
        # Initialize network validation
        self._initialize_ip_validation()
    
    def _load_sandbox_networks(self) -> List[SandboxNetwork]:
        """Load sandbox network configurations"""
        # In production, load from environment/config
        return [
            SandboxNetwork(
                name="primary_sandbox",
                ip_ranges=["10.0.100.0/24", "172.16.100.0/24"],
                interface="eth1",
                is_active=True
            ),
            SandboxNetwork(
                name="backup_sandbox", 
                ip_ranges=["10.0.101.0/24"],
                interface="eth2",
                is_active=False
            ),
            SandboxNetwork(
                name="cloud_sandbox",
                ip_ranges=["192.168.100.0/24"],
                proxy_url="http://sandbox-proxy:8080",
                is_active=True
            )
        ]
    
    def _initialize_ip_validation(self):
        """Initialize IP validation rules"""
        try:
            # Get current external IP to block
            current_ip = self._get_current_external_ip()
            if current_ip:
                self.blocked_user_ips.add(current_ip)
                logger.info(f"Blocked user IP from external scans: {current_ip}")
            
            # Validate sandbox networks
            self._validate_sandbox_networks()
            
            # Select active network
            self._select_active_network()
            
        except Exception as e:
            logger.error(f"Error initializing IP validation: {e}")
            raise
    
    def _get_current_external_ip(self) -> Optional[str]:
        """Get current external IP address"""
        try:
            # Use multiple services for reliability
            ip_services = [
                "https://api.ipify.org",
                "https://ifconfig.me/ip",
                "https://icanhazip.com"
            ]
            
            for service in ip_services:
                try:
                    response = requests.get(service, timeout=5)
                    if response.status_code == 200:
                        ip = response.text.strip()
                        # Validate IP format
                        ipaddress.ip_address(ip)
                        return ip
                except Exception:
                    continue
            
            return None
            
        except Exception as e:
            logger.warning(f"Could not determine external IP: {e}")
            return None
    
    def _validate_sandbox_networks(self):
        """Validate sandbox network configurations"""
        for network in self.sandbox_networks:
            try:
                # Validate IP ranges
                for ip_range in network.ip_ranges:
                    ipaddress.ip_network(ip_range, strict=False)
                
                # Test network connectivity if active
                if network.is_active:
                    self._test_network_connectivity(network)
                    
            except Exception as e:
                logger.error(f"Invalid sandbox network {network.name}: {e}")
                network.is_active = False
    
    def _test_network_connectivity(self, network: SandboxNetwork) -> bool:
        """Test connectivity through sandbox network"""
        try:
            # Test basic connectivity
            if network.proxy_url:
                # Test proxy connectivity
                proxies = {'http': network.proxy_url, 'https': network.proxy_url}
                response = requests.get(
                    "http://httpbin.org/ip", 
                    proxies=proxies, 
                    timeout=10
                )
                if response.status_code == 200:
                    origin_ip = response.json().get('origin', '')
                    logger.info(f"Sandbox network {network.name} test successful, origin IP: {origin_ip}")
                    return True
            
            # Add other connectivity tests as needed
            return True
            
        except Exception as e:
            logger.warning(f"Connectivity test failed for {network.name}: {e}")
            return False
    
    def _select_active_network(self):
        """Select the best available sandbox network"""
        active_networks = [n for n in self.sandbox_networks if n.is_active]
        
        if not active_networks:
            raise RuntimeError("No active sandbox networks available")
        
        # Select primary network (can implement load balancing here)
        self.current_network = active_networks[0]
        logger.info(f"Selected sandbox network: {self.current_network.name}")
    
    def create_sandbox_session(self, timeout: int = 30) -> requests.Session:
        """
        Create HTTP session that routes through sandbox network.
        
        Args:
            timeout: Request timeout in seconds
            
        Returns:
            Configured requests.Session
        """
        if not self.current_network:
            raise RuntimeError("No sandbox network available")
        
        session = requests.Session()
        
        # Configure retry strategy
        retry_strategy = Retry(
            total=3,
            status_forcelist=[429, 500, 502, 503, 504],
            method_whitelist=["HEAD", "GET", "OPTIONS", "POST"],
            backoff_factor=1
        )
        
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        
        # Configure proxy if available
        if self.current_network.proxy_url:
            session.proxies.update({
                'http': self.current_network.proxy_url,
                'https': self.current_network.proxy_url
            })
        
        # Set timeout
        session.request = lambda *args, **kwargs: session.request(*args, **kwargs, timeout=timeout)
        
        # Add headers to identify sandbox traffic
        session.headers.update({
            'User-Agent': 'PhishNet-Sandbox/1.0',
            'X-Sandbox-Network': self.current_network.name,
            'X-Scan-Type': 'automated'
        })
        
        return session
    
    async def create_sandbox_aiohttp_session(self, timeout: int = 30) -> aiohttp.ClientSession:
        """
        Create async HTTP session that routes through sandbox network.
        
        Args:
            timeout: Request timeout in seconds
            
        Returns:
            Configured aiohttp.ClientSession
        """
        if not self.current_network:
            raise RuntimeError("No sandbox network available")
        
        # Configure timeout
        timeout_config = aiohttp.ClientTimeout(total=timeout)
        
        # Configure connector
        connector_kwargs = {}
        
        # Configure proxy if available
        if self.current_network.proxy_url:
            connector_kwargs['proxy'] = self.current_network.proxy_url
        
        connector = aiohttp.TCPConnector(**connector_kwargs)
        
        # Create session
        session = aiohttp.ClientSession(
            connector=connector,
            timeout=timeout_config,
            headers={
                'User-Agent': 'PhishNet-Sandbox/1.0',
                'X-Sandbox-Network': self.current_network.name,
                'X-Scan-Type': 'automated'
            }
        )
        
        return session
    
    def validate_scan_source_ip(self, request_ip: str) -> bool:
        """
        Validate that scan originates from sandbox IP.
        
        Args:
            request_ip: IP address of the scan request
            
        Returns:
            bool: True if IP is from sandbox, False otherwise
        """
        try:
            request_addr = ipaddress.ip_address(request_ip)
            
            # Check if IP is blocked (user device IP)
            if request_ip in self.blocked_user_ips:
                logger.warning(f"Blocked scan from user device IP: {request_ip}")
                return False
            
            # Check if IP is from sandbox networks
            for network in self.sandbox_networks:
                if not network.is_active:
                    continue
                    
                for ip_range in network.ip_ranges:
                    network_obj = ipaddress.ip_network(ip_range, strict=False)
                    if request_addr in network_obj:
                        logger.debug(f"Validated sandbox IP {request_ip} in network {network.name}")
                        return True
            
            logger.warning(f"Scan request from non-sandbox IP: {request_ip}")
            return False
            
        except Exception as e:
            logger.error(f"Error validating scan source IP {request_ip}: {e}")
            return False
    
    def get_sandbox_ip_info(self) -> Dict[str, Any]:
        """Get information about current sandbox IP configuration"""
        try:
            # Get current external IP through sandbox
            session = self.create_sandbox_session(timeout=10)
            response = session.get("http://httpbin.org/ip")
            
            if response.status_code == 200:
                current_ip = response.json().get('origin', '')
            else:
                current_ip = "unknown"
            
            return {
                'current_sandbox_ip': current_ip,
                'sandbox_network': self.current_network.name if self.current_network else None,
                'available_networks': [
                    {
                        'name': n.name,
                        'ip_ranges': n.ip_ranges,
                        'active': n.is_active
                    }
                    for n in self.sandbox_networks
                ],
                'blocked_user_ips': list(self.blocked_user_ips)
            }
            
        except Exception as e:
            logger.error(f"Error getting sandbox IP info: {e}")
            return {'error': str(e)}
    
    def add_blocked_ip(self, ip_address: str):
        """Add IP address to blocked list (e.g., user device IPs)"""
        try:
            # Validate IP format
            ipaddress.ip_address(ip_address)
            self.blocked_user_ips.add(ip_address)
            
            # Cache in Redis for distributed access
            self.redis_client.sadd("blocked_scan_ips", ip_address)
            
            logger.info(f"Added IP to blocked list: {ip_address}")
            
        except Exception as e:
            logger.error(f"Error adding blocked IP {ip_address}: {e}")
    
    def remove_blocked_ip(self, ip_address: str):
        """Remove IP address from blocked list"""
        try:
            self.blocked_user_ips.discard(ip_address)
            
            # Remove from Redis
            self.redis_client.srem("blocked_scan_ips", ip_address)
            
            logger.info(f"Removed IP from blocked list: {ip_address}")
            
        except Exception as e:
            logger.error(f"Error removing blocked IP {ip_address}: {e}")
    
    def load_blocked_ips_from_cache(self):
        """Load blocked IPs from Redis cache"""
        try:
            blocked_ips = self.redis_client.smembers("blocked_scan_ips")
            self.blocked_user_ips.update(blocked_ips)
            logger.info(f"Loaded {len(blocked_ips)} blocked IPs from cache")
            
        except Exception as e:
            logger.error(f"Error loading blocked IPs from cache: {e}")
    
    def switch_sandbox_network(self, network_name: str) -> bool:
        """Switch to a different sandbox network"""
        try:
            target_network = None
            for network in self.sandbox_networks:
                if network.name == network_name and network.is_active:
                    target_network = network
                    break
            
            if not target_network:
                logger.error(f"Sandbox network {network_name} not found or inactive")
                return False
            
            # Test connectivity
            if self._test_network_connectivity(target_network):
                self.current_network = target_network
                logger.info(f"Switched to sandbox network: {network_name}")
                return True
            else:
                logger.error(f"Connectivity test failed for {network_name}")
                return False
                
        except Exception as e:
            logger.error(f"Error switching sandbox network to {network_name}: {e}")
            return False
    
    async def verify_no_user_ip_leakage(self, scan_session) -> Dict[str, Any]:
        """
        Verify that scan session doesn't leak user IP addresses.
        
        Args:
            scan_session: HTTP session to test
            
        Returns:
            Dict with verification results
        """
        try:
            # Test multiple IP detection services
            ip_services = [
                "http://httpbin.org/ip",
                "https://api.ipify.org?format=json",
                "https://ifconfig.me/ip"
            ]
            
            detected_ips = []
            
            for service in ip_services:
                try:
                    if hasattr(scan_session, 'get'):
                        # requests.Session
                        response = scan_session.get(service, timeout=10)
                        if response.status_code == 200:
                            if 'json' in service:
                                ip = response.json().get('ip', response.json().get('origin', ''))
                            else:
                                ip = response.text.strip()
                            detected_ips.append(ip)
                    else:
                        # aiohttp.ClientSession
                        async with scan_session.get(service) as response:
                            if response.status == 200:
                                text = await response.text()
                                if 'json' in service:
                                    data = await response.json()
                                    ip = data.get('ip', data.get('origin', ''))
                                else:
                                    ip = text.strip()
                                detected_ips.append(ip)
                                
                except Exception as e:
                    logger.debug(f"IP detection service {service} failed: {e}")
                    continue
            
            # Validate all detected IPs are from sandbox
            all_valid = True
            invalid_ips = []
            
            for ip in detected_ips:
                if not self.validate_scan_source_ip(ip):
                    all_valid = False
                    invalid_ips.append(ip)
            
            return {
                'valid': all_valid,
                'detected_ips': detected_ips,
                'invalid_ips': invalid_ips,
                'sandbox_network': self.current_network.name if self.current_network else None
            }
            
        except Exception as e:
            logger.error(f"Error verifying IP leakage: {e}")
            return {
                'valid': False,
                'error': str(e)
            }

# Global sandbox IP manager
_sandbox_ip_manager = None

def get_sandbox_ip_manager() -> SandboxIPManager:
    """Get global sandbox IP manager instance"""
    global _sandbox_ip_manager
    if _sandbox_ip_manager is None:
        _sandbox_ip_manager = SandboxIPManager()
        _sandbox_ip_manager.load_blocked_ips_from_cache()
    return _sandbox_ip_manager

def create_secure_scan_session(timeout: int = 30) -> requests.Session:
    """Create secure scan session that routes through sandbox"""
    manager = get_sandbox_ip_manager()
    return manager.create_sandbox_session(timeout)

async def create_secure_async_session(timeout: int = 30) -> aiohttp.ClientSession:
    """Create secure async scan session that routes through sandbox"""
    manager = get_sandbox_ip_manager()
    return await manager.create_sandbox_aiohttp_session(timeout)

def validate_scan_ip(request_ip: str) -> bool:
    """Validate that scan request comes from sandbox IP"""
    manager = get_sandbox_ip_manager()
    return manager.validate_scan_source_ip(request_ip)
