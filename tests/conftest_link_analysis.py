"""
Test Configuration and Utilities for Link Redirect Analysis

Provides test fixtures, mock data, and utilities for comprehensive testing
of the link redirect analysis system.
"""

import json
import asyncio
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from unittest.mock import Mock, AsyncMock, patch

import pytest
import httpx
from playwright.async_api import Browser, BrowserContext, Page

from app.services.link_redirect_analyzer import TLSCertificateDetails, RedirectHopDetails


class MockRedirectServer:
    """Mock server for testing redirect chains."""
    
    def __init__(self):
        self.redirect_chains = {}
        self.response_delays = {}
        self.content_variations = {}
    
    def setup_redirect_chain(self, start_url: str, chain: List[Dict[str, Any]]):
        """Setup a redirect chain for testing."""
        self.redirect_chains[start_url] = chain
    
    def setup_response_delay(self, url: str, delay_ms: int):
        """Setup response delay for URL."""
        self.response_delays[url] = delay_ms
    
    def setup_content_variation(self, url: str, user_agent: str, content: str):
        """Setup content variation based on user agent."""
        if url not in self.content_variations:
            self.content_variations[url] = {}
        self.content_variations[url][user_agent] = content
    
    async def get_response(self, url: str, user_agent: str = "default") -> Mock:
        """Get mock response for URL."""
        # Simulate delay
        if url in self.response_delays:
            await asyncio.sleep(self.response_delays[url] / 1000)
        
        # Check for redirect chain
        if url in self.redirect_chains:
            chain = self.redirect_chains[url]
            if chain:
                next_hop = chain[0]
                response = Mock()
                response.status_code = next_hop.get("status_code", 200)
                response.headers = next_hop.get("headers", {})
                response.content = next_hop.get("content", b"").encode() if isinstance(next_hop.get("content", b""), str) else next_hop.get("content", b"")
                response.url = url
                
                # Remove processed hop
                self.redirect_chains[url] = chain[1:]
                return response
        
        # Check for content variation
        content = "Default content"
        if url in self.content_variations and user_agent in self.content_variations[url]:
            content = self.content_variations[url][user_agent]
        
        response = Mock()
        response.status_code = 200
        response.headers = {}
        response.content = content.encode()
        response.url = url
        return response


class TestDataGenerator:
    """Generate test data for various scenarios."""
    
    @staticmethod
    def create_redirect_hop(
        hop_number: int,
        url: str,
        status_code: int = 200,
        redirect_type: str = "HTTP_REDIRECT",
        location_header: Optional[str] = None,
        suspicious_patterns: Optional[List[str]] = None,
        tls_certificate: Optional[TLSCertificateDetails] = None
    ) -> RedirectHopDetails:
        """Create a redirect hop for testing."""
        return RedirectHopDetails(
            hop_number=hop_number,
            url=url,
            method="GET",
            status_code=status_code,
            redirect_type=redirect_type,
            location_header=location_header,
            hostname=url.split("://")[1].split("/")[0] if "://" in url else url,
            ip_address="93.184.216.34",
            tls_certificate=tls_certificate,
            response_time_ms=100 + hop_number * 50,
            content_hash=f"hash_{hop_number}",
            content_length=1024 * hop_number,
            headers={"Location": location_header} if location_header else {},
            meta_refresh_delay=None,
            javascript_redirects=[],
            suspicious_patterns=suspicious_patterns or [],
            timestamp=datetime.utcnow(),
            final_effective_url=location_header or url
        )
    
    @staticmethod
    def create_tls_certificate(
        common_name: str,
        is_valid: bool = True,
        is_expired: bool = False,
        is_self_signed: bool = False,
        hostname_matches: bool = True,
        validation_errors: Optional[List[str]] = None
    ) -> TLSCertificateDetails:
        """Create TLS certificate details for testing."""
        return TLSCertificateDetails(
            subject=f"CN={common_name}",
            issuer="CN=Test CA, O=Test Organization",
            common_name=common_name,
            san_list=[common_name, f"www.{common_name}"],
            not_before=datetime.utcnow() - timedelta(days=30),
            not_after=datetime.utcnow() + timedelta(days=90 if not is_expired else -10),
            is_valid=is_valid,
            is_self_signed=is_self_signed,
            is_expired=is_expired,
            hostname_matches=hostname_matches,
            fingerprint_sha256="test_fingerprint_123",
            serial_number="123456789",
            signature_algorithm="sha256WithRSAEncryption",
            issuer_organization="Test Organization",
            validation_errors=validation_errors or []
        )
    
    @staticmethod
    def create_multi_hop_redirect_chain(hops: int = 3) -> List[RedirectHopDetails]:
        """Create a multi-hop redirect chain."""
        chain = []
        for i in range(hops):
            is_last = i == hops - 1
            status_code = 200 if is_last else 301
            next_url = f"https://step{i+2}.example.com" if not is_last else None
            
            hop = TestDataGenerator.create_redirect_hop(
                hop_number=i + 1,
                url=f"https://step{i+1}.example.com",
                status_code=status_code,
                location_header=next_url
            )
            chain.append(hop)
        
        return chain
    
    @staticmethod
    def create_suspicious_url_patterns() -> List[Dict[str, Any]]:
        """Create URLs with suspicious patterns."""
        return [
            {
                "url": "https://goog1e.com",
                "patterns": ["homograph_attack", "domain_spoofing"],
                "description": "Google homograph attack"
            },
            {
                "url": "https://paypal-security-verification.update-account.com",
                "patterns": ["subdomain_spoofing", "brand_impersonation", "suspicious_keywords"],
                "description": "PayPal subdomain spoofing"
            },
            {
                "url": "https://bit.ly/3abc123",
                "patterns": ["url_shortener", "obfuscated_destination"],
                "description": "Suspicious URL shortener"
            },
            {
                "url": "https://xn--goog1e-fxa.com",
                "patterns": ["punycode_attack", "internationalized_domain"],
                "description": "Punycode domain attack"
            },
            {
                "url": "https://amazon-com-security.verification-required.com",
                "patterns": ["typosquatting", "brand_impersonation", "suspicious_keywords"],
                "description": "Amazon typosquatting"
            }
        ]
    
    @staticmethod
    def create_cloaking_scenarios() -> List[Dict[str, Any]]:
        """Create cloaking test scenarios."""
        return [
            {
                "name": "User Agent Cloaking",
                "url": "https://cloaking-example.com",
                "responses": {
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64)": "Legitimate content for users",
                    "Googlebot/2.1": "SEO optimized content for search engines",
                    "facebookexternalhit/1.1": "Social media optimized content"
                },
                "expected_cloaking": True,
                "confidence_threshold": 0.7
            },
            {
                "name": "Geographic Cloaking",
                "url": "https://geo-cloaking.com",
                "responses": {
                    "US": "US specific content",
                    "EU": "GDPR compliant content",
                    "CN": "China specific content"
                },
                "expected_cloaking": True,
                "confidence_threshold": 0.8
            },
            {
                "name": "No Cloaking",
                "url": "https://legitimate-site.com",
                "responses": {
                    "default": "Same content for everyone",
                    "mobile": "Same content for everyone",
                    "bot": "Same content for everyone"
                },
                "expected_cloaking": False,
                "confidence_threshold": 0.3
            }
        ]


class MockPlaywrightBrowser:
    """Mock Playwright browser for testing."""
    
    def __init__(self):
        self.contexts = []
        self.pages = []
        self.is_connected = True
    
    async def new_context(self, **kwargs) -> 'MockBrowserContext':
        """Create new browser context."""
        context = MockBrowserContext(self)
        self.contexts.append(context)
        return context
    
    async def close(self):
        """Close browser."""
        self.is_connected = False
        for context in self.contexts:
            await context.close()


class MockBrowserContext:
    """Mock browser context."""
    
    def __init__(self, browser: MockPlaywrightBrowser):
        self.browser = browser
        self.pages = []
        self.is_closed = False
    
    async def __aenter__(self):
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.close()
    
    async def new_page(self) -> 'MockPage':
        """Create new page."""
        page = MockPage(self)
        self.pages.append(page)
        return page
    
    async def close(self):
        """Close context."""
        self.is_closed = True
        for page in self.pages:
            await page.close()


class MockPage:
    """Mock page for browser testing."""
    
    def __init__(self, context: MockBrowserContext):
        self.context = context
        self.url = ""
        self.content_html = "<html><body>Mock content</body></html>"
        self.javascript_redirects = []
        self.is_closed = False
    
    async def goto(self, url: str, **kwargs):
        """Navigate to URL."""
        self.url = url
        # Simulate load time
        await asyncio.sleep(0.1)
    
    async def wait_for_load_state(self, state: str = "load", **kwargs):
        """Wait for load state."""
        await asyncio.sleep(0.05)
    
    async def content(self) -> str:
        """Get page content."""
        return self.content_html
    
    async def evaluate(self, script: str) -> List[str]:
        """Evaluate JavaScript."""
        if "location.href" in script or "window.location" in script:
            return self.javascript_redirects
        return []
    
    async def close(self):
        """Close page."""
        self.is_closed = True
    
    def set_content(self, content: str):
        """Set page content for testing."""
        self.content_html = content
    
    def set_javascript_redirects(self, redirects: List[str]):
        """Set JavaScript redirects for testing."""
        self.javascript_redirects = redirects


@pytest.fixture
def mock_redirect_server():
    """Provide mock redirect server."""
    return MockRedirectServer()


@pytest.fixture
def test_data_generator():
    """Provide test data generator."""
    return TestDataGenerator()


@pytest.fixture
def mock_playwright_browser():
    """Provide mock Playwright browser."""
    return MockPlaywrightBrowser()


@pytest.fixture
def sample_threat_scenarios():
    """Provide sample threat scenarios for testing."""
    return [
        {
            "name": "Safe Redirect Chain",
            "start_url": "https://safe-redirect.com",
            "expected_verdict": "safe",
            "expected_threat_score": 0.2,
            "redirect_count": 2
        },
        {
            "name": "Suspicious Shortened URL",
            "start_url": "https://bit.ly/suspicious",
            "expected_verdict": "suspicious", 
            "expected_threat_score": 0.6,
            "redirect_count": 1
        },
        {
            "name": "Malicious Phishing Chain",
            "start_url": "https://paypal-security.fake-domain.com",
            "expected_verdict": "malicious",
            "expected_threat_score": 0.9,
            "redirect_count": 3
        }
    ]


@pytest.fixture
def performance_test_urls():
    """Provide URLs for performance testing."""
    return [
        f"https://performance-test-{i}.example.com" 
        for i in range(100)
    ]


class TestEnvironmentManager:
    """Manage test environment and cleanup."""
    
    @staticmethod
    def setup_test_environment():
        """Setup test environment."""
        # Setup test database/Redis if needed
        pass
    
    @staticmethod
    def cleanup_test_environment():
        """Cleanup test environment."""
        # Cleanup test data
        pass
    
    @staticmethod
    def create_test_config() -> Dict[str, Any]:
        """Create test configuration."""
        return {
            "max_redirects": 5,
            "max_analysis_time": 10,
            "cache_enabled": True,
            "cache_ttl": 300,
            "browser_enabled": True,
            "cloaking_detection": True,
            "tls_validation": True
        }


# Test markers for different test categories
pytestmark = [
    pytest.mark.asyncio,  # All tests are async
]

# Custom test markers
def pytest_configure(config):
    """Configure pytest with custom markers."""
    config.addinivalue_line(
        "markers", "integration: marks tests as integration tests"
    )
    config.addinivalue_line(
        "markers", "performance: marks tests as performance tests"
    )
    config.addinivalue_line(
        "markers", "network: marks tests that require network access"
    )
    config.addinivalue_line(
        "markers", "browser: marks tests that require browser functionality"
    )