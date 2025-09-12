"""
Analyzer factory for creating and managing service adapters.
Provides production adapters, test stubs, and configuration management.
"""

from typing import Dict, List, Optional, Any, Type
from dataclasses import dataclass
from enum import Enum

from app.config.settings import settings
from app.config.logging import get_logger
from app.services.interfaces import IAnalyzer, AnalysisType, ServiceHealth
from app.services.virustotal import VirusTotalClient, create_virustotal_client
from app.services.abuseipdb import AbuseIPDBClient, create_abuseipdb_client  
from app.services.gemini import GeminiClient, create_gemini_client
from app.services.link_redirect_analyzer import LinkRedirectAnalyzer, create_link_redirect_analyzer
from app.services.threat_aggregator import ThreatAggregator, create_threat_aggregator

logger = get_logger(__name__)


class AnalyzerMode(Enum):
    """Modes for analyzer factory operation."""
    PRODUCTION = "production"
    TESTING = "testing"
    DEVELOPMENT = "development"
    MOCK = "mock"


@dataclass
class AnalyzerConfig:
    """Configuration for individual analyzer services."""
    enabled: bool = True
    api_key: Optional[str] = None
    rate_limit_override: Optional[int] = None
    circuit_breaker_threshold: int = 3
    cache_ttl_seconds: int = 3600
    timeout_seconds: int = 30


@dataclass
class FactoryConfig:
    """Overall configuration for analyzer factory."""
    mode: AnalyzerMode = AnalyzerMode.PRODUCTION
    fallback_enabled: bool = True
    parallel_execution: bool = True
    max_concurrent_analyzers: int = 5
    
    # Service-specific configs
    virustotal: AnalyzerConfig = None
    abuseipdb: AnalyzerConfig = None
    gemini: AnalyzerConfig = None
    
    def __post_init__(self):
        """Initialize default configs if not provided."""
        if self.virustotal is None:
            self.virustotal = AnalyzerConfig(
                enabled=bool(settings.VIRUSTOTAL_API_KEY),
                api_key=settings.VIRUSTOTAL_API_KEY
            )
        
        if self.abuseipdb is None:
            self.abuseipdb = AnalyzerConfig(
                enabled=bool(settings.ABUSEIPDB_API_KEY),
                api_key=settings.ABUSEIPDB_API_KEY
            )
        
        if self.gemini is None:
            self.gemini = AnalyzerConfig(
                enabled=bool(settings.GEMINI_API_KEY),
                api_key=settings.GEMINI_API_KEY
            )


class MockAnalyzer(IAnalyzer):
    """Mock analyzer for testing purposes."""
    
    def __init__(self, service_name: str, mock_score: float = 0.0):
        super().__init__(service_name)
        self.mock_score = mock_score
    
    async def analyze(self, target: str, analysis_type: AnalysisType):
        """Return mock analysis result."""
        import time
        from app.services.interfaces import AnalysisResult
        
        return AnalysisResult(
            service_name=self.service_name,
            analysis_type=analysis_type,
            target=target,
            threat_score=self.mock_score,
            confidence=0.8,
            raw_response={"mock": True, "target": target},
            timestamp=time.time(),
            execution_time_ms=100,
            verdict="mock",
            explanation=f"Mock analysis for {self.service_name}",
            indicators=[f"mock_{self.service_name}_indicator"]
        )
    
    async def health_check(self):
        """Return healthy status for mock."""
        return self._health


class AnalyzerFactory:
    """
    Factory class for creating and managing threat analysis service adapters.
    Handles production adapters, test stubs, and configuration management.
    """
    
    def __init__(self, config: Optional[FactoryConfig] = None):
        self.config = config or FactoryConfig()
        self._analyzers: Dict[str, IAnalyzer] = {}
        self._initialized = False
        
        logger.info(f"AnalyzerFactory initialized in {self.config.mode.value} mode")
    
    async def initialize(self):
        """Initialize all configured analyzers."""
        if self._initialized:
            logger.warning("AnalyzerFactory already initialized")
            return
        
        self._analyzers.clear()
        
        if self.config.mode == AnalyzerMode.MOCK:
            await self._create_mock_analyzers()
        elif self.config.mode in [AnalyzerMode.PRODUCTION, AnalyzerMode.DEVELOPMENT]:
            await self._create_production_analyzers()
        elif self.config.mode == AnalyzerMode.TESTING:
            await self._create_test_analyzers()
        
        # Perform health checks
        await self._initial_health_checks()
        
        self._initialized = True
        logger.info(f"AnalyzerFactory initialized with {len(self._analyzers)} analyzers")
    
    async def _create_production_analyzers(self):
        """Create production analyzer instances."""
        
        # VirusTotal
        if self.config.virustotal.enabled:
            try:
                vt_client = create_virustotal_client(self.config.virustotal.api_key)
                self._analyzers['virustotal'] = vt_client
                logger.info("VirusTotal analyzer created")
            except Exception as e:
                logger.error(f"Failed to create VirusTotal analyzer: {e}")
        
        # AbuseIPDB
        if self.config.abuseipdb.enabled:
            try:
                abuse_client = create_abuseipdb_client(self.config.abuseipdb.api_key)
                self._analyzers['abuseipdb'] = abuse_client
                logger.info("AbuseIPDB analyzer created")
            except Exception as e:
                logger.error(f"Failed to create AbuseIPDB analyzer: {e}")
        
        # Gemini
        if self.config.gemini.enabled:
            try:
                gemini_client = create_gemini_client(self.config.gemini.api_key)
                self._analyzers['gemini'] = gemini_client
                logger.info("Gemini analyzer created")
            except Exception as e:
                logger.error(f"Failed to create Gemini analyzer: {e}")
        
        # Link Redirect Analyzer (no API key required)
        try:
            redirect_analyzer = create_link_redirect_analyzer()
            self._analyzers['link_redirect_analyzer'] = redirect_analyzer
            logger.info("Link Redirect Analyzer created")
        except Exception as e:
            logger.error(f"Failed to create Link Redirect Analyzer: {e}")
        
        # Threat Aggregator
        try:
            threat_aggregator = create_threat_aggregator()
            self._analyzers['threat_aggregator'] = threat_aggregator
            logger.info("Threat Aggregator created")
        except Exception as e:
            logger.error(f"Failed to create Threat Aggregator: {e}")
    
    async def _create_mock_analyzers(self):
        """Create mock analyzers for testing."""
        self._analyzers['virustotal'] = MockAnalyzer("virustotal", mock_score=0.2)
        self._analyzers['abuseipdb'] = MockAnalyzer("abuseipdb", mock_score=0.1)
        self._analyzers['gemini'] = MockAnalyzer("gemini", mock_score=0.3)
        self._analyzers['link_redirect_analyzer'] = MockAnalyzer("link_redirect_analyzer", mock_score=0.15)
        self._analyzers['threat_aggregator'] = MockAnalyzer("threat_aggregator", mock_score=0.25)
        logger.info("Mock analyzers created for testing")
    
    async def _create_test_analyzers(self):
        """Create test-specific analyzers."""
        # For testing, create a mix of real and mock analyzers
        # This allows testing with some real services if keys are available
        
        # Use real analyzers if API keys are available, otherwise mock
        if self.config.virustotal.enabled and self.config.virustotal.api_key:
            self._analyzers['virustotal'] = create_virustotal_client(self.config.virustotal.api_key)
        else:
            self._analyzers['virustotal'] = MockAnalyzer("virustotal", mock_score=0.1)
        
        if self.config.abuseipdb.enabled and self.config.abuseipdb.api_key:
            self._analyzers['abuseipdb'] = create_abuseipdb_client(self.config.abuseipdb.api_key)
        else:
            self._analyzers['abuseipdb'] = MockAnalyzer("abuseipdb", mock_score=0.05)
        
        if self.config.gemini.enabled and self.config.gemini.api_key:
            self._analyzers['gemini'] = create_gemini_client(self.config.gemini.api_key)
        else:
            self._analyzers['gemini'] = MockAnalyzer("gemini", mock_score=0.2)
        
        # Always include link redirect analyzer and threat aggregator in tests
        try:
            self._analyzers['link_redirect_analyzer'] = create_link_redirect_analyzer()
            self._analyzers['threat_aggregator'] = create_threat_aggregator()
        except Exception as e:
            # Fall back to mocks if creation fails
            self._analyzers['link_redirect_analyzer'] = MockAnalyzer("link_redirect_analyzer", mock_score=0.15)
            self._analyzers['threat_aggregator'] = MockAnalyzer("threat_aggregator", mock_score=0.25)
        
        logger.info("Test analyzers created")
    
    async def _initial_health_checks(self):
        """Perform initial health checks on all analyzers."""
        for name, analyzer in self._analyzers.items():
            try:
                health = await analyzer.health_check()
                logger.info(f"Analyzer {name} health: {health.status.value}")
            except Exception as e:
                logger.error(f"Health check failed for {name}: {e}")
    
    def get_analyzers(self) -> Dict[str, IAnalyzer]:
        """Get all available analyzers."""
        if not self._initialized:
            raise RuntimeError("AnalyzerFactory not initialized. Call initialize() first.")
        
        return self._analyzers.copy()
    
    def get_analyzer(self, name: str) -> Optional[IAnalyzer]:
        """Get specific analyzer by name."""
        if not self._initialized:
            raise RuntimeError("AnalyzerFactory not initialized. Call initialize() first.")
        
        return self._analyzers.get(name)
    
    def get_analyzers_for_type(self, analysis_type: AnalysisType) -> List[IAnalyzer]:
        """Get analyzers that support a specific analysis type."""
        if not self._initialized:
            raise RuntimeError("AnalyzerFactory not initialized. Call initialize() first.")
        
        # Map analysis types to analyzer capabilities
        type_mapping = {
            AnalysisType.URL_SCAN: ['virustotal'],
            AnalysisType.IP_REPUTATION: ['abuseipdb', 'virustotal'],
            AnalysisType.TEXT_ANALYSIS: ['gemini'],
            AnalysisType.FILE_HASH: ['virustotal']
        }
        
        analyzer_names = type_mapping.get(analysis_type, [])
        available_analyzers = []
        
        for name in analyzer_names:
            analyzer = self._analyzers.get(name)
            if analyzer and analyzer.is_available:
                available_analyzers.append(analyzer)
        
        return available_analyzers
    
    async def get_service_health(self) -> Dict[str, ServiceHealth]:
        """Get health status of all services."""
        if not self._initialized:
            raise RuntimeError("AnalyzerFactory not initialized. Call initialize() first.")
        
        health_status = {}
        for name, analyzer in self._analyzers.items():
            try:
                health = await analyzer.health_check()
                health_status[name] = health
            except Exception as e:
                logger.error(f"Health check error for {name}: {e}")
                # Create error health status
                from app.services.interfaces import ServiceHealth, ServiceStatus
                health_status[name] = ServiceHealth(
                    status=ServiceStatus.UNAVAILABLE
                )
        
        return health_status
    
    def is_analyzer_available(self, name: str) -> bool:
        """Check if specific analyzer is available."""
        analyzer = self._analyzers.get(name)
        return analyzer is not None and analyzer.is_available
    
    def get_available_analyzer_count(self) -> int:
        """Get count of available analyzers."""
        return sum(1 for analyzer in self._analyzers.values() if analyzer.is_available)
    
    def get_real_analyzers(self) -> Dict[str, IAnalyzer]:
        """
        Get real (non-mock) analyzers for production use.
        Filters out any mock analyzers and returns only production-ready services.
        """
        if not self._initialized:
            raise RuntimeError("AnalyzerFactory not initialized. Call initialize() first.")
        
        real_analyzers = {}
        
        for name, analyzer in self._analyzers.items():
            # Skip mock analyzers
            if isinstance(analyzer, MockAnalyzer):
                continue
            
            # Only include analyzers that are available
            if hasattr(analyzer, 'is_available') and analyzer.is_available:
                real_analyzers[name] = analyzer
            elif hasattr(analyzer, '_health') and analyzer._health.status == ServiceStatus.AVAILABLE:
                real_analyzers[name] = analyzer
            else:
                # Include analyzers that don't have health checks (like threat_aggregator)
                real_analyzers[name] = analyzer
        
        return real_analyzers
    
    async def reconfigure(self, new_config: FactoryConfig):
        """Reconfigure factory with new settings."""
        logger.info("Reconfiguring AnalyzerFactory")
        self.config = new_config
        self._initialized = False
        await self.initialize()
    
    async def shutdown(self):
        """Shutdown all analyzers and cleanup resources."""
        logger.info("Shutting down AnalyzerFactory")
        
        for name, analyzer in self._analyzers.items():
            try:
                # If analyzers have cleanup methods, call them here
                if hasattr(analyzer, 'cleanup'):
                    await analyzer.cleanup()
            except Exception as e:
                logger.error(f"Error shutting down analyzer {name}: {e}")
        
        self._analyzers.clear()
        self._initialized = False
        logger.info("AnalyzerFactory shutdown complete")


# Global factory instance
_factory_instance: Optional[AnalyzerFactory] = None


def get_analyzer_factory() -> AnalyzerFactory:
    """Get or create global analyzer factory instance."""
    global _factory_instance
    
    if _factory_instance is None:
        # Determine mode based on environment
        mode = AnalyzerMode.PRODUCTION
        if settings.DEBUG:
            mode = AnalyzerMode.DEVELOPMENT
        elif getattr(settings, 'TESTING', False):
            mode = AnalyzerMode.TESTING
        
        config = FactoryConfig(mode=mode)
        _factory_instance = AnalyzerFactory(config)
    
    return _factory_instance


async def initialize_global_factory():
    """Initialize the global analyzer factory."""
    factory = get_analyzer_factory()
    if not factory._initialized:
        await factory.initialize()


# Convenience functions for common operations
async def get_production_analyzers() -> Dict[str, IAnalyzer]:
    """Get production analyzers (convenience function)."""
    factory = get_analyzer_factory()
    await factory.initialize()
    return factory.get_analyzers()


async def analyze_with_best_available(
    target: str, 
    analysis_type: AnalysisType
) -> Dict[str, Any]:
    """
    Analyze target with all available analyzers for the given type.
    Returns combined results from all available services.
    """
    factory = get_analyzer_factory()
    await factory.initialize()
    
    analyzers = factory.get_analyzers_for_type(analysis_type)
    if not analyzers:
        raise RuntimeError(f"No analyzers available for {analysis_type.value}")
    
    results = {}
    
    # Run analyzers in parallel if configured
    if factory.config.parallel_execution:
        import asyncio
        
        async def run_analyzer(analyzer):
            try:
                return await analyzer.analyze(target, analysis_type)
            except Exception as e:
                logger.error(f"Analyzer {analyzer.service_name} failed: {e}")
                return None
        
        tasks = [run_analyzer(analyzer) for analyzer in analyzers]
        analyzer_results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for analyzer, result in zip(analyzers, analyzer_results):
            if result and not isinstance(result, Exception):
                results[analyzer.service_name] = result
    else:
        # Sequential execution
        for analyzer in analyzers:
            try:
                result = await analyzer.analyze(target, analysis_type)
                results[analyzer.service_name] = result
            except Exception as e:
                logger.error(f"Analyzer {analyzer.service_name} failed: {e}")
    
    return results
