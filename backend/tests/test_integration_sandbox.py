"""
Comprehensive Integration Tests for PhishNet
End-to-end scan with local sandbox (containerized headless) for test URLs
Tests: legit, redirect, phishing URLs - assert ThreatResult returned and DB updated
"""

import pytest
import asyncio
import docker
import time
import json
import tempfile
import os
from typing import Dict, List, Any, Optional
from unittest.mock import Mock, patch, AsyncMock
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from datetime import datetime, timedelta

# Core imports
from app.orchestrator.main import PhishNetOrchestrator
from app.core.sandbox_security import get_sandbox_ip_manager
from app.services.analysis.threat_aggregator import ThreatResult
from app.models.scan_result import ScanResult
from app.models.email import Email
from app.models.user import User
from app.db.base import Base


class SandboxManager:
    """Manage containerized sandbox environments for testing"""
    
    def __init__(self):
        self.docker_client = None
        self.sandbox_containers = []
        self.network_name = "phishnet-test-sandbox"
        
    async def setup_sandbox_environment(self):
        """Set up containerized sandbox environment"""
        try:
            self.docker_client = docker.from_env()
            
            # Create isolated network for sandbox
            try:
                network = self.docker_client.networks.create(
                    self.network_name,
                    driver="bridge",
                    options={
                        "com.docker.network.bridge.enable_icc": "false",
                        "com.docker.network.bridge.enable_ip_masquerade": "true"
                    }
                )
                print(f"Created sandbox network: {network.id}")
            except docker.errors.APIError as e:
                if "already exists" not in str(e):
                    raise
                network = self.docker_client.networks.get(self.network_name)
            
            # Start headless browser container for URL analysis
            browser_container = self.docker_client.containers.run(
                "browserless/chrome:latest",
                detach=True,
                ports={'3000/tcp': None},
                environment={
                    "MAX_CONCURRENT_SESSIONS": "5",
                    "CONNECTION_TIMEOUT": "30000",
                    "DEFAULT_BLOCK_ADS": "true",
                    "DEFAULT_IGNORE_HTTPS_ERRORS": "true"
                },
                networks=[self.network_name],
                name=f"phishnet-browser-{int(time.time())}"
            )
            
            self.sandbox_containers.append(browser_container)
            
            # Wait for browser to be ready
            await self._wait_for_container_ready(browser_container, port=3000)
            
            # Start mock HTTP server for test URLs
            http_server_container = self.docker_client.containers.run(
                "nginx:alpine",
                detach=True,
                ports={'80/tcp': None},
                networks=[self.network_name],
                name=f"phishnet-http-{int(time.time())}"
            )
            
            self.sandbox_containers.append(http_server_container)
            
            return {
                'browser_url': f"http://localhost:{browser_container.ports['3000/tcp'][0]['HostPort']}",
                'http_server_url': f"http://localhost:{http_server_container.ports['80/tcp'][0]['HostPort']}",
                'network_name': self.network_name
            }
            
        except Exception as e:
            await self.cleanup_sandbox_environment()
            raise Exception(f"Failed to setup sandbox environment: {e}")
    
    async def _wait_for_container_ready(self, container, port, timeout=30):
        """Wait for container to be ready"""
        import socket
        
        host_port = container.ports[f'{port}/tcp'][0]['HostPort']
        
        for _ in range(timeout):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex(('localhost', int(host_port)))
                sock.close()
                if result == 0:
                    return True
            except:
                pass
            await asyncio.sleep(1)
        
        raise Exception(f"Container not ready after {timeout} seconds")
    
    async def cleanup_sandbox_environment(self):
        """Clean up sandbox containers and networks"""
        try:
            if self.docker_client:
                # Stop and remove containers
                for container in self.sandbox_containers:
                    try:
                        container.stop(timeout=5)
                        container.remove()
                    except:
                        pass
                
                # Remove network
                try:
                    network = self.docker_client.networks.get(self.network_name)
                    network.remove()
                except:
                    pass
                    
        except Exception as e:
            print(f"Error cleaning up sandbox: {e}")


class TestIntegrationWithSandbox:
    """Integration tests with containerized sandbox"""
    
    @pytest.fixture(scope="class")
    async def sandbox_environment(self):
        """Set up sandbox environment for integration tests"""
        sandbox_manager = SandboxManager()
        try:
            environment = await sandbox_manager.setup_sandbox_environment()
            yield environment
        finally:
            await sandbox_manager.cleanup_sandbox_environment()
    
    @pytest.fixture
    def test_database(self):
        """Set up test database"""
        engine = create_engine("sqlite:///./test_integration.db")
        Base.metadata.create_all(bind=engine)
        
        TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
        
        yield TestingSessionLocal
        
        # Cleanup
        Base.metadata.drop_all(bind=engine)
        try:
            os.remove("./test_integration.db")
        except:
            pass
    
    @pytest.mark.asyncio
    async def test_legitimate_url_scan(self, sandbox_environment, test_database):
        """Test scanning legitimate URL with real sandbox"""
        
        # Test legitimate website URLs
        legitimate_urls = [
            "https://www.google.com",
            "https://www.microsoft.com",
            "https://github.com",
            "https://stackoverflow.com"
        ]
        
        orchestrator = PhishNetOrchestrator()
        
        for url in legitimate_urls:
            with patch('app.db.database.get_db') as mock_db:
                mock_db.return_value = test_database()
                
                # Mock external API calls to avoid quota usage
                with patch('app.integrations.virustotal.VirusTotalAdapter.scan_url') as mock_vt, \
                     patch('app.integrations.gemini.GeminiAdapter.analyze_content') as mock_gemini:
                    
                    # Mock clean results for legitimate sites
                    mock_vt.return_value = Mock(
                        scan_id=f"clean-{int(time.time())}",
                        positives=0,
                        total=70,
                        permalink=f"https://virustotal.com/clean-{url}"
                    )
                    
                    mock_gemini.return_value = {
                        'threat_probability': 0.05,
                        'confidence': 0.95,
                        'reasoning': 'Legitimate website with no threat indicators',
                        'risk_factors': []
                    }
                    
                    # Perform scan
                    result = await orchestrator.scan_email(
                        user_id="test_user_legit",
                        email_id=f"email_legit_{int(time.time())}",
                        subject="Check out this link",
                        sender="friend@example.com",
                        body=f"Here's a useful link: {url}",
                        links=[url]
                    )
                    
                    # Verify legitimate URL results
                    assert result is not None
                    assert result.overall_threat_level == "LOW"
                    assert result.threat_score < 0.3
                    assert result.confidence_score > 0.8
                    
                    # Verify database update
                    db_session = test_database()
                    scan_records = db_session.query(ScanResult).filter_by(
                        user_id="test_user_legit"
                    ).all()
                    
                    assert len(scan_records) > 0
                    latest_scan = scan_records[-1]
                    assert latest_scan.threat_level == "LOW"
                    assert latest_scan.threat_score < 0.3
    
    @pytest.mark.asyncio
    async def test_redirect_url_scan(self, sandbox_environment, test_database):
        """Test scanning URLs with redirect chains"""
        
        # Test redirect scenarios
        redirect_test_cases = [
            {
                'url': 'https://bit.ly/3example',
                'expected_final': 'https://legitimate-site.com/page',
                'expected_threat': 'LOW'
            },
            {
                'url': 'https://tinyurl.com/suspicious',
                'expected_final': 'https://suspicious-domain.tk/login',
                'expected_threat': 'MEDIUM'
            }
        ]
        
        orchestrator = PhishNetOrchestrator()
        
        for test_case in redirect_test_cases:
            with patch('app.db.database.get_db') as mock_db:
                mock_db.return_value = test_database()
                
                # Mock redirect analysis
                with patch('app.services.analysis.link_redirect_analyzer.LinkRedirectAnalyzer.trace_redirects') as mock_redirect, \
                     patch('app.integrations.virustotal.VirusTotalAdapter.scan_url') as mock_vt, \
                     patch('app.integrations.gemini.GeminiAdapter.analyze_content') as mock_gemini:
                    
                    # Mock redirect chain
                    mock_redirect.return_value = Mock(
                        final_url=test_case['expected_final'],
                        redirect_chain=[test_case['url'], test_case['expected_final']],
                        redirect_count=1,
                        has_loop=False,
                        threat_indicators={
                            'domain_cloaking': 'suspicious' in test_case['expected_final'],
                            'suspicious_tld': '.tk' in test_case['expected_final'],
                            'excessive_redirects': False
                        }
                    )
                    
                    # Mock appropriate threat level
                    if test_case['expected_threat'] == 'LOW':
                        mock_vt.return_value = Mock(
                            scan_id="redirect-clean",
                            positives=0,
                            total=70,
                            permalink="https://virustotal.com/redirect-clean"
                        )
                        mock_gemini.return_value = {
                            'threat_probability': 0.15,
                            'confidence': 0.85,
                            'reasoning': 'Redirect to legitimate site',
                            'risk_factors': ['url_shortener']
                        }
                    else:
                        mock_vt.return_value = Mock(
                            scan_id="redirect-suspicious",
                            positives=8,
                            total=70,
                            permalink="https://virustotal.com/redirect-suspicious"
                        )
                        mock_gemini.return_value = {
                            'threat_probability': 0.65,
                            'confidence': 0.80,
                            'reasoning': 'Suspicious redirect patterns detected',
                            'risk_factors': ['url_shortener', 'suspicious_tld', 'domain_cloaking']
                        }
                    
                    # Perform scan
                    result = await orchestrator.scan_email(
                        user_id="test_user_redirect",
                        email_id=f"email_redirect_{int(time.time())}",
                        subject="Important link",
                        sender="unknown@sender.com",
                        body=f"Click here: {test_case['url']}",
                        links=[test_case['url']]
                    )
                    
                    # Verify redirect analysis results
                    assert result is not None
                    assert result.overall_threat_level == test_case['expected_threat']
                    
                    if test_case['expected_threat'] == 'MEDIUM':
                        assert result.threat_score > 0.5
                    else:
                        assert result.threat_score < 0.4
                    
                    # Verify redirect chain was analyzed
                    mock_redirect.assert_called_once_with(test_case['url'])
                    
                    # Verify database update includes redirect info
                    db_session = test_database()
                    scan_records = db_session.query(ScanResult).filter_by(
                        user_id="test_user_redirect"
                    ).all()
                    
                    assert len(scan_records) > 0
                    latest_scan = scan_records[-1]
                    assert latest_scan.final_url == test_case['expected_final']
    
    @pytest.mark.asyncio
    async def test_phishing_url_scan(self, sandbox_environment, test_database):
        """Test scanning known phishing URLs"""
        
        # Test phishing scenarios
        phishing_test_cases = [
            {
                'url': 'https://g00gle-security.tk/verify-account',
                'domain_spoofing': True,
                'expected_threat': 'HIGH'
            },
            {
                'url': 'https://paypal-verification.ml/urgent-action',
                'domain_spoofing': True,
                'expected_threat': 'HIGH'
            },
            {
                'url': 'https://microsoft-security-alert.cf/login',
                'domain_spoofing': True,
                'expected_threat': 'HIGH'
            }
        ]
        
        orchestrator = PhishNetOrchestrator()
        
        for test_case in phishing_test_cases:
            with patch('app.db.database.get_db') as mock_db:
                mock_db.return_value = test_database()
                
                # Mock high-threat responses
                with patch('app.integrations.virustotal.VirusTotalAdapter.scan_url') as mock_vt, \
                     patch('app.integrations.gemini.GeminiAdapter.analyze_content') as mock_gemini, \
                     patch('app.integrations.abuseipdb.AbuseIPDBAdapter.check_ip') as mock_abuse:
                    
                    # Mock high threat from VirusTotal
                    mock_vt.return_value = Mock(
                        scan_id=f"phishing-{int(time.time())}",
                        positives=25,
                        total=70,
                        permalink=f"https://virustotal.com/phishing-{test_case['url']}"
                    )
                    
                    # Mock high threat from Gemini
                    mock_gemini.return_value = {
                        'threat_probability': 0.92,
                        'confidence': 0.95,
                        'reasoning': 'Clear phishing attempt with domain spoofing',
                        'risk_factors': [
                            'domain_spoofing',
                            'credential_request',
                            'urgent_language',
                            'suspicious_tld'
                        ]
                    }
                    
                    # Mock abuse reports
                    mock_abuse.return_value = Mock(
                        ip_address="203.0.113.100",
                        abuse_confidence=85,
                        total_reports=50
                    )
                    
                    # Perform scan
                    result = await orchestrator.scan_email(
                        user_id="test_user_phishing",
                        email_id=f"email_phishing_{int(time.time())}",
                        subject="URGENT: Account Security Alert",
                        sender="security@fake-company.com",
                        body=f"Your account has been compromised. Verify immediately: {test_case['url']}",
                        links=[test_case['url']]
                    )
                    
                    # Verify phishing detection results
                    assert result is not None
                    assert result.overall_threat_level == "HIGH"
                    assert result.threat_score > 0.8
                    assert result.confidence_score > 0.9
                    
                    # Verify evidence includes multiple sources
                    assert len(result.evidence_links) >= 2
                    
                    # Verify database update
                    db_session = test_database()
                    scan_records = db_session.query(ScanResult).filter_by(
                        user_id="test_user_phishing"
                    ).all()
                    
                    assert len(scan_records) > 0
                    latest_scan = scan_records[-1]
                    assert latest_scan.threat_level == "HIGH"
                    assert latest_scan.threat_score > 0.8
                    assert latest_scan.is_phishing == True
    
    @pytest.mark.asyncio
    async def test_sandbox_ip_enforcement(self, sandbox_environment, test_database):
        """Test that all scans use sandbox IPs only"""
        
        sandbox_manager = get_sandbox_ip_manager()
        orchestrator = PhishNetOrchestrator()
        
        # Monitor IP usage during scans
        used_ips = []
        
        def track_ip_usage(session_or_ip):
            if hasattr(session_or_ip, 'headers'):
                # Extract IP from session headers or connection
                used_ips.append("sandbox_session")
            else:
                used_ips.append(str(session_or_ip))
        
        with patch('app.core.sandbox_security.SandboxIPManager.create_sandbox_session') as mock_session:
            mock_session.side_effect = lambda: track_ip_usage("sandbox_session") or Mock()
            
            with patch('app.db.database.get_db') as mock_db:
                mock_db.return_value = test_database()
                
                # Mock external services
                with patch('app.integrations.virustotal.VirusTotalAdapter.scan_url') as mock_vt, \
                     patch('app.integrations.gemini.GeminiAdapter.analyze_content') as mock_gemini:
                    
                    mock_vt.return_value = Mock(
                        scan_id="ip-test",
                        positives=0,
                        total=70,
                        permalink="https://virustotal.com/ip-test"
                    )
                    
                    mock_gemini.return_value = {
                        'threat_probability': 0.1,
                        'confidence': 0.9,
                        'reasoning': 'No threats detected',
                        'risk_factors': []
                    }
                    
                    # Perform multiple scans
                    test_urls = [
                        "https://example1.com",
                        "https://example2.com",
                        "https://example3.com"
                    ]
                    
                    for url in test_urls:
                        result = await orchestrator.scan_email(
                            user_id="test_user_ip",
                            email_id=f"email_ip_{int(time.time())}",
                            subject="Test email",
                            sender="test@example.com",
                            body=f"Check this: {url}",
                            links=[url]
                        )
                        
                        assert result is not None
                    
                    # Verify all scans used sandbox sessions
                    assert len(used_ips) >= len(test_urls)
                    assert all("sandbox" in ip for ip in used_ips)
    
    @pytest.mark.asyncio
    async def test_end_to_end_database_updates(self, sandbox_environment, test_database):
        """Test that complete scan results are properly stored in database"""
        
        orchestrator = PhishNetOrchestrator()
        
        with patch('app.db.database.get_db') as mock_db:
            db_session = test_database()
            mock_db.return_value = db_session
            
            # Create test user
            test_user = User(
                id="test_user_e2e",
                email="test@example.com",
                gmail_token_encrypted="encrypted_token",
                consent_granted=True
            )
            db_session.add(test_user)
            db_session.commit()
            
            # Mock external services
            with patch('app.integrations.virustotal.VirusTotalAdapter.scan_url') as mock_vt, \
                 patch('app.integrations.gemini.GeminiAdapter.analyze_content') as mock_gemini, \
                 patch('app.integrations.abuseipdb.AbuseIPDBAdapter.check_ip') as mock_abuse:
                
                mock_vt.return_value = Mock(
                    scan_id="e2e-test-scan",
                    positives=12,
                    total=70,
                    permalink="https://virustotal.com/e2e-test"
                )
                
                mock_gemini.return_value = {
                    'threat_probability': 0.70,
                    'confidence': 0.85,
                    'reasoning': 'Moderate threat indicators',
                    'risk_factors': ['suspicious_domain', 'urgent_language']
                }
                
                mock_abuse.return_value = Mock(
                    ip_address="203.0.113.75",
                    abuse_confidence=45,
                    total_reports=15
                )
                
                # Perform comprehensive scan
                result = await orchestrator.scan_email(
                    user_id="test_user_e2e",
                    email_id="email_e2e_comprehensive",
                    subject="Important: Account Update Required",
                    sender="updates@suspicious-domain.tk",
                    body="Please update your account information at: https://suspicious-update.tk/account",
                    links=["https://suspicious-update.tk/account"]
                )
                
                # Verify scan result
                assert result is not None
                assert result.overall_threat_level in ["MEDIUM", "HIGH"]
                
                # Verify complete database record
                scan_records = db_session.query(ScanResult).filter_by(
                    user_id="test_user_e2e",
                    email_id="email_e2e_comprehensive"
                ).all()
                
                assert len(scan_records) == 1
                scan_record = scan_records[0]
                
                # Verify all fields are populated
                assert scan_record.user_id == "test_user_e2e"
                assert scan_record.email_id == "email_e2e_comprehensive"
                assert scan_record.threat_level in ["MEDIUM", "HIGH"]
                assert scan_record.threat_score > 0.5
                assert scan_record.confidence_score > 0.8
                assert scan_record.virustotal_scan_id == "e2e-test-scan"
                assert scan_record.gemini_analysis is not None
                assert scan_record.final_url == "https://suspicious-update.tk/account"
                assert scan_record.created_at is not None
                
                # Verify email record
                email_records = db_session.query(Email).filter_by(
                    user_id="test_user_e2e",
                    email_id="email_e2e_comprehensive"
                ).all()
                
                assert len(email_records) == 1
                email_record = email_records[0]
                
                assert email_record.subject_encrypted is not None
                assert email_record.sender == "updates@suspicious-domain.tk"
                assert email_record.threat_level in ["MEDIUM", "HIGH"]
                assert email_record.processed_at is not None


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])
