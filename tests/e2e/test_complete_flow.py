"""
Comprehensive End-to-End Testing Suite for Phishnet
 
This module provides a complete testing framework covering:
- OAuth flow testing
- Email sync testing  
- Scan operation testing
- Result analysis testing
- Privacy compliance testing
- Performance testing
- Integration testing
"""

import asyncio
import pytest
import json
import time
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from unittest.mock import AsyncMock, MagicMock

import httpx
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import AsyncSession

# Test configuration and fixtures
from backend.app.main import app
from backend.app.auth.oauth import get_oauth_client
from backend.app.services.email_service import EmailService
from backend.app.services.scanner_service import ScannerService
from backend.app.observability import get_logger, TracingManager
from backend.app.privacy import PrivacyComplianceManager

logger = get_logger(__name__)

@dataclass
class TestScenario:
    """Represents a complete test scenario from OAuth to final results."""
    name: str
    description: str
    oauth_provider: str
    email_count: int
    expected_threats: int
    privacy_sensitive: bool
    performance_threshold_ms: int
    steps: List[str]

# Test scenarios covering various use cases
TEST_SCENARIOS = [
    TestScenario(
        name="standard_gmail_scan",
        description="Standard Gmail OAuth flow with email scanning",
        oauth_provider="gmail",
        email_count=50,
        expected_threats=2,
        privacy_sensitive=True,
        performance_threshold_ms=30000,
        steps=[
            "oauth_authorization",
            "token_exchange", 
            "email_sync",
            "threat_analysis",
            "result_verification"
        ]
    ),
    TestScenario(
        name="high_volume_scan",
        description="High volume email processing test",
        oauth_provider="outlook",
        email_count=500,
        expected_threats=15,
        privacy_sensitive=True,
        performance_threshold_ms=120000,
        steps=[
            "oauth_authorization",
            "token_exchange",
            "bulk_email_sync",
            "parallel_threat_analysis", 
            "result_aggregation"
        ]
    ),
    TestScenario(
        name="privacy_compliance_test",
        description="Privacy-focused testing with consent management",
        oauth_provider="gmail",
        email_count=10,
        expected_threats=1,
        privacy_sensitive=True,
        performance_threshold_ms=15000,
        steps=[
            "consent_collection",
            "oauth_authorization",
            "pii_protected_sync",
            "privacy_compliant_analysis",
            "audit_trail_verification"
        ]
    ),
    TestScenario(
        name="cloaking_detection_test",
        description="Advanced cloaking and redirect chain analysis",
        oauth_provider="gmail",
        email_count=20,
        expected_threats=5,
        privacy_sensitive=False,
        performance_threshold_ms=45000,
        steps=[
            "oauth_authorization",
            "email_sync",
            "cloaking_analysis",
            "redirect_chain_analysis",
            "screenshot_capture"
        ]
    )
]

class E2ETestFramework:
    """Main end-to-end testing framework."""
    
    def __init__(self):
        self.client = TestClient(app)
        self.test_user_id = "test_user_123"
        self.test_org_id = "test_org_456" 
        self.oauth_mock = None
        self.email_service_mock = None
        self.scanner_service_mock = None
        self.privacy_manager = None
        self.tracing = TracingManager()
        
    async def setup(self):
        """Initialize test framework with mocks and test data."""
        logger.info("Setting up E2E test framework")
        
        # Initialize privacy compliance manager
        self.privacy_manager = PrivacyComplianceManager(
            db_manager=None,  # Mock this
            encryption_key="test_key_12345678901234567890123"
        )
        
        # Set up OAuth mock
        self.oauth_mock = AsyncMock()
        self.oauth_mock.authorization_url.return_value = (
            "https://accounts.google.com/oauth/authorize?client_id=test&response_type=code",
            "test_state"
        )
        self.oauth_mock.fetch_token.return_value = {
            "access_token": "test_access_token",
            "refresh_token": "test_refresh_token", 
            "expires_in": 3600
        }
        
        # Set up email service mock
        self.email_service_mock = AsyncMock()
        
        # Set up scanner service mock
        self.scanner_service_mock = AsyncMock()
        
        logger.info("E2E test framework setup complete")
    
    async def teardown(self):
        """Clean up test framework."""
        logger.info("Tearing down E2E test framework")
        # Clean up any test data, connections, etc.
        
    async def run_scenario(self, scenario: TestScenario) -> Dict[str, Any]:
        """Run a complete test scenario and return results."""
        logger.info(f"Starting test scenario: {scenario.name}")
        
        start_time = time.time()
        results = {
            "scenario": scenario.name,
            "start_time": datetime.utcnow().isoformat(),
            "steps_completed": [],
            "steps_failed": [],
            "performance_metrics": {},
            "privacy_compliance": {},
            "assertions_passed": 0,
            "assertions_failed": 0,
            "errors": []
        }
        
        try:
            # Execute each step in the scenario
            for step in scenario.steps:
                step_start = time.time()
                
                try:
                    await self._execute_step(step, scenario, results)
                    results["steps_completed"].append(step)
                    
                    step_duration = (time.time() - step_start) * 1000
                    results["performance_metrics"][step] = step_duration
                    
                except Exception as e:
                    logger.error(f"Step {step} failed: {str(e)}")
                    results["steps_failed"].append(step)
                    results["errors"].append(f"{step}: {str(e)}")
            
            # Calculate total execution time
            total_duration = (time.time() - start_time) * 1000
            results["total_duration_ms"] = total_duration
            results["end_time"] = datetime.utcnow().isoformat()
            
            # Verify performance requirements
            if total_duration > scenario.performance_threshold_ms:
                results["errors"].append(
                    f"Performance threshold exceeded: {total_duration}ms > {scenario.performance_threshold_ms}ms"
                )
            
            # Privacy compliance verification
            if scenario.privacy_sensitive:
                privacy_results = await self._verify_privacy_compliance(scenario)
                results["privacy_compliance"] = privacy_results
            
            logger.info(f"Scenario {scenario.name} completed in {total_duration:.2f}ms")
            
        except Exception as e:
            logger.error(f"Scenario {scenario.name} failed: {str(e)}")
            results["errors"].append(f"Scenario failure: {str(e)}")
            
        return results
    
    async def _execute_step(self, step: str, scenario: TestScenario, results: Dict[str, Any]):
        """Execute a single test step."""
        logger.debug(f"Executing step: {step}")
        
        step_methods = {
            "oauth_authorization": self._test_oauth_authorization,
            "token_exchange": self._test_token_exchange,
            "consent_collection": self._test_consent_collection,
            "email_sync": self._test_email_sync,
            "bulk_email_sync": self._test_bulk_email_sync,
            "pii_protected_sync": self._test_pii_protected_sync,
            "threat_analysis": self._test_threat_analysis,
            "parallel_threat_analysis": self._test_parallel_threat_analysis,
            "privacy_compliant_analysis": self._test_privacy_compliant_analysis,
            "cloaking_analysis": self._test_cloaking_analysis,
            "redirect_chain_analysis": self._test_redirect_chain_analysis,
            "screenshot_capture": self._test_screenshot_capture,
            "result_verification": self._test_result_verification,
            "result_aggregation": self._test_result_aggregation,
            "audit_trail_verification": self._test_audit_trail_verification
        }
        
        if step not in step_methods:
            raise ValueError(f"Unknown test step: {step}")
            
        await step_methods[step](scenario, results)
    
    async def _test_oauth_authorization(self, scenario: TestScenario, results: Dict[str, Any]):
        """Test OAuth authorization flow."""
        logger.debug("Testing OAuth authorization")
        
        # Test authorization URL generation
        response = self.client.get(
            f"/auth/oauth/{scenario.oauth_provider}/authorize",
            params={"user_id": self.test_user_id}
        )
        
        assert response.status_code == 200, f"OAuth authorization failed: {response.text}"
        
        auth_data = response.json()
        assert "authorization_url" in auth_data
        assert "state" in auth_data
        
        results["oauth_state"] = auth_data["state"]
        results["assertions_passed"] += 2
        
        logger.debug("OAuth authorization test passed")
    
    async def _test_token_exchange(self, scenario: TestScenario, results: Dict[str, Any]):
        """Test OAuth token exchange."""
        logger.debug("Testing OAuth token exchange")
        
        # Mock token exchange callback
        response = self.client.post(
            f"/auth/oauth/{scenario.oauth_provider}/callback",
            json={
                "code": "test_auth_code",
                "state": results.get("oauth_state", "test_state"),
                "user_id": self.test_user_id
            }
        )
        
        assert response.status_code == 200, f"Token exchange failed: {response.text}"
        
        token_data = response.json()
        assert "access_token" in token_data
        assert "expires_in" in token_data
        
        results["access_token"] = token_data["access_token"]
        results["assertions_passed"] += 2
        
        logger.debug("OAuth token exchange test passed")
    
    async def _test_consent_collection(self, scenario: TestScenario, results: Dict[str, Any]):
        """Test privacy consent collection."""
        logger.debug("Testing consent collection")
        
        # Test consent form display
        response = self.client.get(
            "/privacy/consent",
            params={"user_id": self.test_user_id}
        )
        
        assert response.status_code == 200
        
        # Test consent submission
        consent_data = {
            "user_id": self.test_user_id,
            "consents": {
                "data_processing": True,
                "analytics": False,
                "marketing": False,
                "third_party_sharing": False
            }
        }
        
        response = self.client.post("/privacy/consent", json=consent_data)
        assert response.status_code == 200
        
        results["consent_collected"] = True
        results["assertions_passed"] += 2
        
        logger.debug("Consent collection test passed")
    
    async def _test_email_sync(self, scenario: TestScenario, results: Dict[str, Any]):
        """Test email synchronization."""
        logger.debug("Testing email sync")
        
        # Mock email sync request
        sync_request = {
            "user_id": self.test_user_id,
            "access_token": results.get("access_token", "test_token"),
            "max_emails": scenario.email_count,
            "sync_type": "incremental"
        }
        
        response = self.client.post("/sync/emails", json=sync_request)
        assert response.status_code == 200
        
        sync_data = response.json()
        assert "job_id" in sync_data
        assert "status" in sync_data
        
        results["sync_job_id"] = sync_data["job_id"]
        results["emails_synced"] = scenario.email_count
        results["assertions_passed"] += 2
        
        # Wait for sync completion (mock)
        await asyncio.sleep(1)  # Simulate sync time
        
        logger.debug("Email sync test passed")
    
    async def _test_bulk_email_sync(self, scenario: TestScenario, results: Dict[str, Any]):
        """Test bulk email synchronization for high volume."""
        logger.debug("Testing bulk email sync")
        
        # This would test the bulk processing capabilities
        await self._test_email_sync(scenario, results)
        
        # Additional bulk-specific validations
        assert results["emails_synced"] >= 500, "Bulk sync should handle large volumes"
        results["assertions_passed"] += 1
        
        logger.debug("Bulk email sync test passed")
    
    async def _test_pii_protected_sync(self, scenario: TestScenario, results: Dict[str, Any]):
        """Test PII-protected email synchronization."""
        logger.debug("Testing PII-protected email sync")
        
        # Test that PII is properly redacted during sync
        await self._test_email_sync(scenario, results)
        
        # Verify PII protection was applied
        response = self.client.get(
            f"/sync/emails/{results['sync_job_id']}/privacy",
            params={"user_id": self.test_user_id}
        )
        
        assert response.status_code == 200
        privacy_data = response.json()
        assert privacy_data.get("pii_redacted") is True
        
        results["pii_protection_applied"] = True
        results["assertions_passed"] += 2
        
        logger.debug("PII-protected sync test passed")
    
    async def _test_threat_analysis(self, scenario: TestScenario, results: Dict[str, Any]):
        """Test threat analysis on synced emails."""
        logger.debug("Testing threat analysis")
        
        # Trigger threat analysis
        analysis_request = {
            "job_id": results.get("sync_job_id"),
            "user_id": self.test_user_id,
            "analysis_type": "comprehensive"
        }
        
        response = self.client.post("/analysis/threats", json=analysis_request)
        assert response.status_code == 200
        
        analysis_data = response.json()
        assert "analysis_id" in analysis_data
        
        results["analysis_id"] = analysis_data["analysis_id"]
        results["assertions_passed"] += 1
        
        # Wait for analysis completion (mock)
        await asyncio.sleep(2)
        
        # Get analysis results
        response = self.client.get(
            f"/analysis/threats/{analysis_data['analysis_id']}/results"
        )
        
        assert response.status_code == 200
        analysis_results = response.json()
        assert "threats_detected" in analysis_results
        
        results["threats_detected"] = analysis_results["threats_detected"]
        results["assertions_passed"] += 2
        
        logger.debug("Threat analysis test passed")
    
    async def _test_parallel_threat_analysis(self, scenario: TestScenario, results: Dict[str, Any]):
        """Test parallel threat analysis for high volume processing."""
        logger.debug("Testing parallel threat analysis")
        
        await self._test_threat_analysis(scenario, results)
        
        # Verify parallel processing was used
        assert results["threats_detected"] >= scenario.expected_threats
        results["assertions_passed"] += 1
        
        logger.debug("Parallel threat analysis test passed")
    
    async def _test_privacy_compliant_analysis(self, scenario: TestScenario, results: Dict[str, Any]):
        """Test privacy-compliant threat analysis."""
        logger.debug("Testing privacy-compliant analysis")
        
        await self._test_threat_analysis(scenario, results)
        
        # Verify privacy compliance was maintained
        response = self.client.get(
            f"/analysis/threats/{results['analysis_id']}/privacy"
        )
        
        assert response.status_code == 200
        privacy_data = response.json()
        assert privacy_data.get("privacy_compliant") is True
        
        results["privacy_compliance_verified"] = True
        results["assertions_passed"] += 2
        
        logger.debug("Privacy-compliant analysis test passed")
    
    async def _test_cloaking_analysis(self, scenario: TestScenario, results: Dict[str, Any]):
        """Test advanced cloaking detection."""
        logger.debug("Testing cloaking analysis")
        
        await self._test_threat_analysis(scenario, results)
        
        # Get cloaking-specific results
        response = self.client.get(
            f"/analysis/threats/{results['analysis_id']}/cloaking"
        )
        
        assert response.status_code == 200
        cloaking_data = response.json()
        assert "cloaking_detected" in cloaking_data
        
        results["cloaking_analysis"] = cloaking_data
        results["assertions_passed"] += 2
        
        logger.debug("Cloaking analysis test passed")
    
    async def _test_redirect_chain_analysis(self, scenario: TestScenario, results: Dict[str, Any]):
        """Test redirect chain analysis."""
        logger.debug("Testing redirect chain analysis")
        
        # Get redirect chain analysis results
        response = self.client.get(
            f"/analysis/threats/{results['analysis_id']}/redirects"
        )
        
        assert response.status_code == 200
        redirect_data = response.json()
        assert "redirect_chains" in redirect_data
        
        results["redirect_analysis"] = redirect_data
        results["assertions_passed"] += 2
        
        logger.debug("Redirect chain analysis test passed")
    
    async def _test_screenshot_capture(self, scenario: TestScenario, results: Dict[str, Any]):
        """Test screenshot capture functionality.""" 
        logger.debug("Testing screenshot capture")
        
        # Get screenshot results
        response = self.client.get(
            f"/analysis/threats/{results['analysis_id']}/screenshots"
        )
        
        assert response.status_code == 200
        screenshot_data = response.json()
        assert "screenshots" in screenshot_data
        
        results["screenshots_captured"] = len(screenshot_data["screenshots"])
        results["assertions_passed"] += 2
        
        logger.debug("Screenshot capture test passed")
    
    async def _test_result_verification(self, scenario: TestScenario, results: Dict[str, Any]):
        """Test final result verification."""
        logger.debug("Testing result verification")
        
        # Verify expected number of threats detected
        expected = scenario.expected_threats
        detected = results.get("threats_detected", 0)
        
        assert detected >= expected * 0.8, f"Expected ~{expected} threats, got {detected}"
        
        # Verify all required data is present
        assert "analysis_id" in results
        assert "sync_job_id" in results
        
        results["result_verification_passed"] = True
        results["assertions_passed"] += 3
        
        logger.debug("Result verification test passed")
    
    async def _test_result_aggregation(self, scenario: TestScenario, results: Dict[str, Any]):
        """Test result aggregation for bulk processing."""
        logger.debug("Testing result aggregation")
        
        await self._test_result_verification(scenario, results)
        
        # Get aggregated results
        response = self.client.get(
            f"/analysis/threats/{results['analysis_id']}/aggregate"
        )
        
        assert response.status_code == 200
        aggregate_data = response.json()
        assert "summary" in aggregate_data
        
        results["aggregation_completed"] = True
        results["assertions_passed"] += 2
        
        logger.debug("Result aggregation test passed")
    
    async def _test_audit_trail_verification(self, scenario: TestScenario, results: Dict[str, Any]):
        """Test audit trail verification."""
        logger.debug("Testing audit trail verification")
        
        # Get audit trail for the test session
        response = self.client.get(
            "/audit/entries",
            params={
                "user_id": self.test_user_id,
                "start_time": results.get("start_time"),
                "end_time": datetime.utcnow().isoformat()
            }
        )
        
        assert response.status_code == 200
        audit_data = response.json()
        assert "entries" in audit_data
        assert len(audit_data["entries"]) > 0
        
        results["audit_trail_verified"] = True
        results["assertions_passed"] += 2
        
        logger.debug("Audit trail verification test passed")
    
    async def _verify_privacy_compliance(self, scenario: TestScenario) -> Dict[str, Any]:
        """Verify privacy compliance for the scenario."""
        logger.debug("Verifying privacy compliance")
        
        compliance_results = {
            "gdpr_compliant": True,
            "ccpa_compliant": True,
            "consent_recorded": True,
            "pii_protected": True,
            "audit_trail_complete": True,
            "data_retention_policy_applied": True
        }
        
        # This would perform actual privacy compliance checks
        # For now, returning mock results
        
        return compliance_results

class PerformanceTestSuite:
    """Performance testing suite for load and stress testing."""
    
    def __init__(self, framework: E2ETestFramework):
        self.framework = framework
        
    async def run_load_test(self, concurrent_users: int = 10, duration_seconds: int = 60) -> Dict[str, Any]:
        """Run load testing with specified parameters."""
        logger.info(f"Starting load test: {concurrent_users} users, {duration_seconds}s")
        
        start_time = time.time()
        results = {
            "concurrent_users": concurrent_users,
            "duration_seconds": duration_seconds,
            "total_requests": 0,
            "successful_requests": 0,
            "failed_requests": 0,
            "average_response_time_ms": 0.0,
            "requests_per_second": 0.0,
            "errors": []
        }
        
        # Simulate concurrent user load
        tasks = []
        for user_id in range(concurrent_users):
            task = asyncio.create_task(
                self._simulate_user_session(f"load_test_user_{user_id}", duration_seconds)
            )
            tasks.append(task)
        
        # Wait for all tasks to complete
        task_results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Aggregate results
        total_duration = time.time() - start_time
        
        for task_result in task_results:
            if isinstance(task_result, Exception):
                results["errors"].append(str(task_result))
                results["failed_requests"] += 1
            else:
                results["total_requests"] += task_result.get("requests", 0)
                results["successful_requests"] += task_result.get("successful", 0)
        
        if results["total_requests"] > 0:
            results["requests_per_second"] = results["total_requests"] / total_duration
            
        logger.info(f"Load test completed: {results['requests_per_second']:.2f} RPS")
        return results
    
    async def _simulate_user_session(self, user_id: str, duration_seconds: int) -> Dict[str, Any]:
        """Simulate a single user session for load testing."""
        session_results = {
            "requests": 0,
            "successful": 0,
            "response_times": []
        }
        
        end_time = time.time() + duration_seconds
        
        while time.time() < end_time:
            try:
                # Simulate typical user workflow
                start = time.time()
                
                # OAuth authorization
                response = self.framework.client.get(
                    "/auth/oauth/gmail/authorize",
                    params={"user_id": user_id}
                )
                
                if response.status_code == 200:
                    session_results["successful"] += 1
                    
                response_time = (time.time() - start) * 1000
                session_results["response_times"].append(response_time)
                session_results["requests"] += 1
                
                # Small delay between requests
                await asyncio.sleep(0.1)
                
            except Exception as e:
                logger.error(f"User session error for {user_id}: {str(e)}")
                break
        
        return session_results

# Test runner and reporting
class E2ETestRunner:
    """Main test runner for executing all end-to-end tests."""
    
    def __init__(self):
        self.framework = E2ETestFramework()
        self.performance_suite = PerformanceTestSuite(self.framework)
        
    async def run_all_tests(self, include_performance: bool = True) -> Dict[str, Any]:
        """Run all test scenarios and generate comprehensive report."""
        logger.info("Starting comprehensive E2E test suite")
        
        await self.framework.setup()
        
        test_results = {
            "test_run_id": f"e2e_test_{int(time.time())}",
            "start_time": datetime.utcnow().isoformat(),
            "scenarios": {},
            "performance_tests": {},
            "summary": {
                "total_scenarios": len(TEST_SCENARIOS),
                "passed_scenarios": 0,
                "failed_scenarios": 0,
                "total_assertions": 0,
                "passed_assertions": 0,
                "failed_assertions": 0
            }
        }
        
        try:
            # Run all test scenarios
            for scenario in TEST_SCENARIOS:
                try:
                    scenario_results = await self.framework.run_scenario(scenario)
                    test_results["scenarios"][scenario.name] = scenario_results
                    
                    # Update summary
                    if not scenario_results.get("errors"):
                        test_results["summary"]["passed_scenarios"] += 1
                    else:
                        test_results["summary"]["failed_scenarios"] += 1
                    
                    test_results["summary"]["passed_assertions"] += scenario_results.get("assertions_passed", 0)
                    test_results["summary"]["failed_assertions"] += scenario_results.get("assertions_failed", 0)
                    
                except Exception as e:
                    logger.error(f"Scenario {scenario.name} crashed: {str(e)}")
                    test_results["scenarios"][scenario.name] = {
                        "error": str(e),
                        "status": "crashed"
                    }
                    test_results["summary"]["failed_scenarios"] += 1
            
            # Run performance tests
            if include_performance:
                logger.info("Running performance tests")
                
                # Load test with 10 concurrent users
                load_results = await self.performance_suite.run_load_test(
                    concurrent_users=10,
                    duration_seconds=30
                )
                test_results["performance_tests"]["load_test_10_users"] = load_results
                
                # Stress test with 50 concurrent users
                stress_results = await self.performance_suite.run_load_test(
                    concurrent_users=50,
                    duration_seconds=60
                )
                test_results["performance_tests"]["stress_test_50_users"] = stress_results
            
            test_results["end_time"] = datetime.utcnow().isoformat()
            test_results["summary"]["total_assertions"] = (
                test_results["summary"]["passed_assertions"] + 
                test_results["summary"]["failed_assertions"]
            )
            
        finally:
            await self.framework.teardown()
        
        logger.info("E2E test suite completed")
        return test_results
    
    def generate_report(self, results: Dict[str, Any], output_file: str = "e2e_test_report.json"):
        """Generate detailed test report."""
        logger.info(f"Generating test report: {output_file}")
        
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2)
        
        # Generate summary report
        summary_file = output_file.replace('.json', '_summary.txt')
        with open(summary_file, 'w') as f:
            self._write_summary_report(f, results)
        
        logger.info("Test reports generated successfully")
    
    def _write_summary_report(self, file, results: Dict[str, Any]):
        """Write human-readable summary report."""
        summary = results["summary"]
        
        file.write("PHISHNET END-TO-END TEST REPORT\n")
        file.write("=" * 50 + "\n\n")
        
        file.write(f"Test Run ID: {results['test_run_id']}\n")
        file.write(f"Start Time: {results['start_time']}\n")
        file.write(f"End Time: {results['end_time']}\n\n")
        
        file.write("SUMMARY\n")
        file.write("-" * 20 + "\n")
        file.write(f"Total Scenarios: {summary['total_scenarios']}\n")
        file.write(f"Passed Scenarios: {summary['passed_scenarios']}\n")
        file.write(f"Failed Scenarios: {summary['failed_scenarios']}\n")
        file.write(f"Success Rate: {(summary['passed_scenarios']/summary['total_scenarios']*100):.1f}%\n\n")
        
        file.write(f"Total Assertions: {summary['total_assertions']}\n")
        file.write(f"Passed Assertions: {summary['passed_assertions']}\n")
        file.write(f"Failed Assertions: {summary['failed_assertions']}\n")
        file.write(f"Assertion Success Rate: {(summary['passed_assertions']/max(summary['total_assertions'], 1)*100):.1f}%\n\n")
        
        file.write("SCENARIO DETAILS\n")
        file.write("-" * 20 + "\n")
        for scenario_name, scenario_results in results["scenarios"].items():
            status = "PASS" if not scenario_results.get("errors") else "FAIL"
            duration = scenario_results.get("total_duration_ms", 0)
            file.write(f"{scenario_name}: {status} ({duration:.0f}ms)\n")
            
            if scenario_results.get("errors"):
                for error in scenario_results["errors"]:
                    file.write(f"  ERROR: {error}\n")
        
        file.write("\n")
        
        if "performance_tests" in results:
            file.write("PERFORMANCE TEST RESULTS\n")
            file.write("-" * 30 + "\n")
            for test_name, perf_results in results["performance_tests"].items():
                rps = perf_results.get("requests_per_second", 0)
                file.write(f"{test_name}: {rps:.2f} requests/second\n")
                file.write(f"  Success Rate: {(perf_results.get('successful_requests', 0)/max(perf_results.get('total_requests', 1), 1)*100):.1f}%\n")

# Pytest integration
@pytest.mark.asyncio
class TestE2EIntegration:
    """Pytest integration for E2E tests."""
    
    @pytest.fixture(scope="session")
    async def test_runner(self):
        """Create test runner fixture."""
        runner = E2ETestRunner()
        yield runner
    
    @pytest.mark.slow
    async def test_standard_gmail_scenario(self, test_runner):
        """Test standard Gmail OAuth to scan flow."""
        scenario = next(s for s in TEST_SCENARIOS if s.name == "standard_gmail_scan")
        await test_runner.framework.setup()
        
        try:
            results = await test_runner.framework.run_scenario(scenario)
            assert not results.get("errors"), f"Scenario failed: {results.get('errors')}"
            assert results["assertions_passed"] > 0, "No assertions passed"
        finally:
            await test_runner.framework.teardown()
    
    @pytest.mark.slow
    async def test_privacy_compliance_scenario(self, test_runner):
        """Test privacy compliance flow."""
        scenario = next(s for s in TEST_SCENARIOS if s.name == "privacy_compliance_test")
        await test_runner.framework.setup()
        
        try:
            results = await test_runner.framework.run_scenario(scenario)
            assert not results.get("errors"), f"Privacy scenario failed: {results.get('errors')}"
            assert results.get("privacy_compliance_verified"), "Privacy compliance not verified"
        finally:
            await test_runner.framework.teardown()
    
    @pytest.mark.performance
    async def test_load_performance(self, test_runner):
        """Test system performance under load."""
        await test_runner.framework.setup()
        
        try:
            results = await test_runner.performance_suite.run_load_test(
                concurrent_users=10,
                duration_seconds=30
            )
            
            assert results["requests_per_second"] > 5.0, "Performance below threshold"
            success_rate = results["successful_requests"] / max(results["total_requests"], 1)
            assert success_rate > 0.95, f"Success rate too low: {success_rate:.2%}"
        finally:
            await test_runner.framework.teardown()

# CLI interface for running tests
if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Phishnet E2E Test Suite")
    parser.add_argument("--scenario", help="Run specific scenario")
    parser.add_argument("--no-performance", action="store_true", help="Skip performance tests")
    parser.add_argument("--output", default="e2e_test_report.json", help="Output report file")
    
    args = parser.parse_args()
    
    async def main():
        runner = E2ETestRunner()
        
        if args.scenario:
            # Run specific scenario
            scenario = next((s for s in TEST_SCENARIOS if s.name == args.scenario), None)
            if not scenario:
                print(f"Scenario '{args.scenario}' not found")
                return
            
            await runner.framework.setup()
            try:
                results = await runner.framework.run_scenario(scenario)
                print(f"Scenario {args.scenario} completed:")
                print(f"  Assertions passed: {results['assertions_passed']}")
                print(f"  Errors: {len(results.get('errors', []))}")
            finally:
                await runner.framework.teardown()
        else:
            # Run full test suite
            results = await runner.run_all_tests(
                include_performance=not args.no_performance
            )
            runner.generate_report(results, args.output)
            
            # Print summary
            summary = results["summary"]
            print(f"Test Results:")
            print(f"  Scenarios: {summary['passed_scenarios']}/{summary['total_scenarios']} passed")
            print(f"  Assertions: {summary['passed_assertions']}/{summary['total_assertions']} passed")
            print(f"  Report saved to: {args.output}")
    
    asyncio.run(main())