"""
Unified Threat Intelligence Service.

This module integrates all components: third-party API adapters, caching, resilience patterns,
and privacy protection into a single secure and efficient threat intelligence service.
"""

import asyncio
import logging
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple
from dataclasses import dataclass, field

from .threat_intel import (
    VirusTotalClient, AbuseIPDBClient, GeminiClient,
    ThreatIntelligence, APIResponse, APIStatus, ResourceType, ThreatLevel
)
from .resilience import ResilientAPIClient, CircuitBreaker, FallbackHandler
from .caching import ThreatIntelligenceCache, CacheConfig
from .privacy import PrivacyAwareAPIWrapper, PIISanitizer

logger = logging.getLogger(__name__)


@dataclass
class ThreatIntelligenceConfig:
    """Configuration for the unified threat intelligence service."""
    # API Keys
    virustotal_api_key: Optional[str] = None
    abuseipdb_api_key: Optional[str] = None
    gemini_api_key: Optional[str] = None
    
    # Redis Configuration
    redis_url: str = "redis://localhost:6379"
    cache_enabled: bool = True
    
    # Privacy Configuration
    pii_sanitization_enabled: bool = True
    audit_logging_enabled: bool = True
    
    # Service Configuration
    enable_virustotal: bool = True
    enable_abuseipdb: bool = True
    enable_gemini: bool = True
    
    # Fallback Configuration
    fallback_enabled: bool = True
    require_at_least_one_service: bool = True


@dataclass
class ServiceHealth:
    """Health status of a threat intelligence service."""
    service_name: str
    is_healthy: bool
    circuit_breaker_state: str
    last_success: Optional[datetime] = None
    last_failure: Optional[datetime] = None
    quota_remaining: Optional[int] = None
    error_message: Optional[str] = None


@dataclass
class ThreatAnalysisResult:
    """Complete threat analysis result with metadata."""
    resource: str
    resource_type: ResourceType
    primary_result: Optional[ThreatIntelligence] = None
    service_results: Dict[str, APIResponse] = field(default_factory=dict)
    aggregated_score: float = 0.0
    confidence: float = 0.0
    sources_used: List[str] = field(default_factory=list)
    cache_hit: bool = False
    privacy_protected: bool = False
    audit_logs: List[Dict[str, Any]] = field(default_factory=list)
    processing_time: float = 0.0
    errors: List[str] = field(default_factory=list)


class UnifiedThreatIntelligenceService:
    """Unified service that orchestrates all threat intelligence operations."""
    
    def __init__(self, config: ThreatIntelligenceConfig):
        self.config = config
        self.logger = logging.getLogger(f"{__name__}.unified")
        
        # Initialize components
        self.cache = None
        self.sanitizer = None
        self.services = {}
        self.resilient_clients = {}
        self.privacy_wrappers = {}
        
        # Initialize if enabled
        if config.cache_enabled:
            self.cache = ThreatIntelligenceCache(config.redis_url)
        
        if config.pii_sanitization_enabled:
            self.sanitizer = PIISanitizer()
        
        # Service health tracking
        self.service_health = {}
    
    async def initialize(self):
        """Initialize all services and connections."""
        self.logger.info("Initializing Unified Threat Intelligence Service")
        
        # Initialize VirusTotal
        if self.config.enable_virustotal and self.config.virustotal_api_key:
            try:
                vt_client = VirusTotalClient(self.config.virustotal_api_key)
                self.services["virustotal"] = vt_client
                
                # Wrap with resilience patterns
                resilient_vt = ResilientAPIClient(vt_client, "virustotal")
                self.resilient_clients["virustotal"] = resilient_vt
                
                # Wrap with privacy protection
                if self.sanitizer:
                    privacy_vt = PrivacyAwareAPIWrapper(vt_client, "virustotal", self.sanitizer)
                    self.privacy_wrappers["virustotal"] = privacy_vt
                
                self.logger.info("VirusTotal client initialized")
                
            except Exception as e:
                self.logger.error(f"Failed to initialize VirusTotal: {str(e)}")
        
        # Initialize AbuseIPDB
        if self.config.enable_abuseipdb and self.config.abuseipdb_api_key:
            try:
                abuseipdb_client = AbuseIPDBClient(self.config.abuseipdb_api_key)
                self.services["abuseipdb"] = abuseipdb_client
                
                # Wrap with resilience patterns
                resilient_abuse = ResilientAPIClient(abuseipdb_client, "abuseipdb")
                self.resilient_clients["abuseipdb"] = resilient_abuse
                
                # Wrap with privacy protection
                if self.sanitizer:
                    privacy_abuse = PrivacyAwareAPIWrapper(abuseipdb_client, "abuseipdb", self.sanitizer)
                    self.privacy_wrappers["abuseipdb"] = privacy_abuse
                
                self.logger.info("AbuseIPDB client initialized")
                
            except Exception as e:
                self.logger.error(f"Failed to initialize AbuseIPDB: {str(e)}")
        
        # Initialize Gemini
        if self.config.enable_gemini and self.config.gemini_api_key:
            try:
                gemini_client = GeminiClient(self.config.gemini_api_key)
                self.services["gemini"] = gemini_client
                
                # Wrap with resilience patterns
                resilient_gemini = ResilientAPIClient(gemini_client, "gemini")
                self.resilient_clients["gemini"] = resilient_gemini
                
                # Wrap with privacy protection
                if self.sanitizer:
                    privacy_gemini = PrivacyAwareAPIWrapper(gemini_client, "gemini", self.sanitizer)
                    self.privacy_wrappers["gemini"] = privacy_gemini
                
                self.logger.info("Gemini client initialized")
                
            except Exception as e:
                self.logger.error(f"Failed to initialize Gemini: {str(e)}")
        
        # Test cache connection
        if self.cache:
            try:
                health = await self.cache.health_check()
                if health["status"] == "healthy":
                    self.logger.info("Cache connection healthy")
                else:
                    self.logger.warning(f"Cache connection degraded: {health}")
            except Exception as e:
                self.logger.error(f"Cache health check failed: {str(e)}")
        
        # Check if we have at least one service
        if self.config.require_at_least_one_service and not self.services:
            raise RuntimeError("No threat intelligence services are available")
        
        self.logger.info(f"Initialized {len(self.services)} threat intelligence services")
    
    async def analyze_url(self, url: str) -> ThreatAnalysisResult:
        """Comprehensive URL analysis using all available services."""
        start_time = asyncio.get_event_loop().time()
        
        result = ThreatAnalysisResult(
            resource=url,
            resource_type=ResourceType.URL
        )
        
        # Check cache first
        cached_results = {}
        if self.cache:
            for service_name in self.services.keys():
                if service_name in ["virustotal", "gemini"]:  # Services that support URLs
                    cached = await self.cache.get(url, ResourceType.URL, service_name)
                    if cached:
                        cached_results[service_name] = cached
                        result.cache_hit = True
        
        # Analyze with available services
        tasks = []
        
        # VirusTotal URL analysis
        if "virustotal" in self.services and "virustotal" not in cached_results:
            if self.config.pii_sanitization_enabled and "virustotal" in self.privacy_wrappers:
                tasks.append(self._safe_analyze_url(url, "virustotal"))
            else:
                tasks.append(self._analyze_url_with_service(url, "virustotal"))
        
        # Gemini URL analysis
        if "gemini" in self.services and "gemini" not in cached_results:
            if self.config.pii_sanitization_enabled and "gemini" in self.privacy_wrappers:
                tasks.append(self._safe_analyze_url(url, "gemini"))
            else:
                tasks.append(self._analyze_url_with_service(url, "gemini"))
        
        # Execute analysis tasks
        if tasks:
            task_results = await asyncio.gather(*tasks, return_exceptions=True)
            
            for i, task_result in enumerate(task_results):
                if isinstance(task_result, Exception):
                    result.errors.append(f"Service analysis failed: {str(task_result)}")
                else:
                    service_name, api_response, audit_log = task_result
                    result.service_results[service_name] = api_response
                    
                    if audit_log:
                        result.audit_logs.append(audit_log)
                        result.privacy_protected = True
                    
                    # Cache successful results
                    if self.cache and api_response.success and api_response.data:
                        await self.cache.set(url, ResourceType.URL, service_name, api_response)
        
        # Add cached results
        result.service_results.update(cached_results)
        
        # Aggregate results
        result.primary_result, result.aggregated_score, result.confidence = self._aggregate_results(
            result.service_results
        )
        
        result.sources_used = list(result.service_results.keys())
        result.processing_time = asyncio.get_event_loop().time() - start_time
        
        return result
    
    async def analyze_ip(self, ip_address: str) -> ThreatAnalysisResult:
        """Comprehensive IP analysis using available services."""
        start_time = asyncio.get_event_loop().time()
        
        result = ThreatAnalysisResult(
            resource=ip_address,
            resource_type=ResourceType.IP_ADDRESS
        )
        
        # Check cache first
        cached_results = {}
        if self.cache:
            for service_name in ["abuseipdb"]:  # Services that support IPs
                cached = await self.cache.get(ip_address, ResourceType.IP_ADDRESS, service_name)
                if cached:
                    cached_results[service_name] = cached
                    result.cache_hit = True
        
        # AbuseIPDB IP analysis
        if "abuseipdb" in self.services and "abuseipdb" not in cached_results:
            try:
                if self.config.pii_sanitization_enabled and "abuseipdb" in self.privacy_wrappers:
                    api_response, audit_log = await self.privacy_wrappers["abuseipdb"].safe_analyze_ip(ip_address)
                    result.audit_logs.append(audit_log)
                    result.privacy_protected = True
                else:
                    api_response = await self.resilient_clients["abuseipdb"].resilient_call("analyze_ip", ip_address)
                
                result.service_results["abuseipdb"] = api_response
                
                # Cache successful results
                if self.cache and api_response.success and api_response.data:
                    await self.cache.set(ip_address, ResourceType.IP_ADDRESS, "abuseipdb", api_response)
                    
            except Exception as e:
                result.errors.append(f"AbuseIPDB analysis failed: {str(e)}")
        
        # Add cached results
        result.service_results.update(cached_results)
        
        # Aggregate results
        result.primary_result, result.aggregated_score, result.confidence = self._aggregate_results(
            result.service_results
        )
        
        result.sources_used = list(result.service_results.keys())
        result.processing_time = asyncio.get_event_loop().time() - start_time
        
        return result
    
    async def analyze_content(self, content: str) -> ThreatAnalysisResult:
        """Comprehensive content analysis using Gemini."""
        start_time = asyncio.get_event_loop().time()
        
        result = ThreatAnalysisResult(
            resource=content[:100] + "..." if len(content) > 100 else content,
            resource_type=ResourceType.EMAIL_ADDRESS  # Using as content placeholder
        )
        
        # Content analysis with Gemini
        if "gemini" in self.services:
            try:
                if self.config.pii_sanitization_enabled and "gemini" in self.privacy_wrappers:
                    api_response, audit_log = await self.privacy_wrappers["gemini"].safe_analyze_content(content)
                    result.audit_logs.append(audit_log)
                    result.privacy_protected = True
                else:
                    api_response = await self.resilient_clients["gemini"].resilient_call("analyze_content", content)
                
                result.service_results["gemini"] = api_response
                    
            except Exception as e:
                result.errors.append(f"Gemini content analysis failed: {str(e)}")
        
        # Aggregate results
        result.primary_result, result.aggregated_score, result.confidence = self._aggregate_results(
            result.service_results
        )
        
        result.sources_used = list(result.service_results.keys())
        result.processing_time = asyncio.get_event_loop().time() - start_time
        
        return result
    
    async def _safe_analyze_url(self, url: str, service_name: str) -> Tuple[str, APIResponse, Dict[str, Any]]:
        """Analyze URL with privacy protection."""
        privacy_wrapper = self.privacy_wrappers[service_name]
        api_response, audit_log = await privacy_wrapper.safe_analyze_url(url)
        return service_name, api_response, audit_log
    
    async def _analyze_url_with_service(self, url: str, service_name: str) -> Tuple[str, APIResponse, None]:
        """Analyze URL without privacy protection."""
        resilient_client = self.resilient_clients[service_name]
        api_response = await resilient_client.resilient_call("analyze_url", url)
        return service_name, api_response, None
    
    def _aggregate_results(self, service_results: Dict[str, APIResponse]) -> Tuple[Optional[ThreatIntelligence], float, float]:
        """Aggregate results from multiple services."""
        if not service_results:
            return None, 0.0, 0.0
        
        valid_results = []
        for service_name, response in service_results.items():
            if response.success and response.data:
                valid_results.append((service_name, response.data))
        
        if not valid_results:
            return None, 0.0, 0.0
        
        # Weight services differently
        service_weights = {
            "virustotal": 0.4,    # High weight for URL/file analysis
            "abuseipdb": 0.3,     # Medium weight for IP analysis
            "gemini": 0.3         # Medium weight for content analysis
        }
        
        total_score = 0.0
        total_weight = 0.0
        total_confidence = 0.0
        
        # Find highest threat level
        max_threat_level = ThreatLevel.SAFE
        primary_result = None
        
        for service_name, threat_intel in valid_results:
            weight = service_weights.get(service_name, 0.2)
            
            # Calculate weighted score
            from .threat_intel.base import calculate_threat_score
            score = calculate_threat_score(threat_intel.threat_level, threat_intel.confidence)
            weighted_score = score * weight
            
            total_score += weighted_score
            total_weight += weight
            total_confidence += threat_intel.confidence * weight
            
            # Track highest threat
            threat_levels = [ThreatLevel.SAFE, ThreatLevel.LOW, ThreatLevel.MEDIUM, ThreatLevel.HIGH, ThreatLevel.CRITICAL]
            if threat_levels.index(threat_intel.threat_level) > threat_levels.index(max_threat_level):
                max_threat_level = threat_intel.threat_level
                primary_result = threat_intel
        
        # Calculate final scores
        final_score = total_score / total_weight if total_weight > 0 else 0.0
        final_confidence = total_confidence / total_weight if total_weight > 0 else 0.0
        
        return primary_result, final_score, final_confidence
    
    async def get_service_health(self) -> Dict[str, ServiceHealth]:
        """Get health status of all services."""
        health_status = {}
        
        for service_name, resilient_client in self.resilient_clients.items():
            try:
                client_health = resilient_client.get_health_status()
                circuit_stats = client_health["circuit_breaker"]
                quota_info = client_health.get("quota")
                
                health_status[service_name] = ServiceHealth(
                    service_name=service_name,
                    is_healthy=circuit_stats["state"] == "closed",
                    circuit_breaker_state=circuit_stats["state"],
                    quota_remaining=quota_info.get("requests_remaining") if quota_info else None,
                    last_success=datetime.fromisoformat(circuit_stats["last_success"]) if circuit_stats.get("last_success") else None,
                    last_failure=datetime.fromisoformat(circuit_stats["last_failure"]) if circuit_stats.get("last_failure") else None
                )
                
            except Exception as e:
                health_status[service_name] = ServiceHealth(
                    service_name=service_name,
                    is_healthy=False,
                    circuit_breaker_state="unknown",
                    error_message=str(e)
                )
        
        return health_status
    
    async def get_cache_stats(self) -> Dict[str, Any]:
        """Get cache statistics."""
        if self.cache:
            return await self.cache.get_cache_stats()
        return {"cache_disabled": True}
    
    async def get_privacy_summary(self) -> Dict[str, Any]:
        """Get privacy protection summary."""
        if not self.privacy_wrappers:
            return {"privacy_protection_disabled": True}
        
        summary = {}
        for service_name, wrapper in self.privacy_wrappers.items():
            summary[service_name] = wrapper.get_privacy_summary()
        
        return summary
    
    async def close(self):
        """Close all connections and cleanup resources."""
        self.logger.info("Shutting down Unified Threat Intelligence Service")
        
        # Close API clients
        for service in self.services.values():
            if hasattr(service, 'close'):
                await service.close()
        
        # Close cache
        if self.cache:
            await self.cache.close()
        
        self.logger.info("Shutdown complete")


# Example usage
async def example_usage():
    """Example of how to use the unified service."""
    # Configuration
    config = ThreatIntelligenceConfig(
        virustotal_api_key="your_vt_key",
        abuseipdb_api_key="your_abuse_key",
        gemini_api_key="your_gemini_key",
        redis_url="redis://localhost:6379",
        cache_enabled=True,
        pii_sanitization_enabled=True
    )
    
    # Initialize service
    service = UnifiedThreatIntelligenceService(config)
    await service.initialize()
    
    try:
        # Analyze URL
        url_result = await service.analyze_url("https://suspicious-site.com")
        print(f"URL Analysis: {url_result.aggregated_score:.2f} confidence: {url_result.confidence:.2f}")
        print(f"Sources: {url_result.sources_used}")
        print(f"Cache hit: {url_result.cache_hit}")
        print(f"Privacy protected: {url_result.privacy_protected}")
        
        # Analyze IP
        ip_result = await service.analyze_ip("185.220.101.182")
        print(f"IP Analysis: {ip_result.aggregated_score:.2f}")
        
        # Analyze content
        content = "Urgent! Your account will be suspended. Click here to verify."
        content_result = await service.analyze_content(content)
        print(f"Content Analysis: {content_result.aggregated_score:.2f}")
        
        # Get health status
        health = await service.get_service_health()
        for service_name, status in health.items():
            print(f"{service_name}: {'healthy' if status.is_healthy else 'unhealthy'}")
        
    finally:
        await service.close()


if __name__ == "__main__":
    asyncio.run(example_usage())