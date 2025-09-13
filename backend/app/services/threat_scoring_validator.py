"""
Test vectors and validation for threat scoring consistency.
Provides known test cases with expected outcomes for validating analyzer performance.
"""

import json
import time
import asyncio
from typing import Dict, Any, List, Tuple, Optional
from dataclasses import dataclass, asdict
from enum import Enum

from app.config.logging import get_logger
from app.orchestrator.real_threat_orchestrator import create_real_threat_orchestrator
from app.services.analyzer_factory import get_analyzer_factory

logger = get_logger(__name__)


class TestVectorType(Enum):
    """Types of test vectors."""
    PHISHING_EMAIL = "phishing_email"
    LEGITIMATE_EMAIL = "legitimate_email"
    MALICIOUS_URL = "malicious_url"
    SAFE_URL = "safe_url"
    SUSPICIOUS_REDIRECT = "suspicious_redirect"
    IP_REPUTATION = "ip_reputation"


@dataclass
class ExpectedOutcome:
    """Expected outcome for a test vector."""
    threat_score_min: float
    threat_score_max: float
    threat_level: str  # safe, low, medium, high, critical
    should_contain_indicators: List[str]
    should_not_contain_indicators: List[str]
    confidence_threshold: float
    verdict_pattern: str  # regex pattern for verdict


@dataclass
class TestVector:
    """Individual test vector with input data and expected outcome."""
    id: str
    name: str
    description: str
    test_type: TestVectorType
    input_data: Dict[str, Any]
    expected_outcome: ExpectedOutcome
    priority: int = 1  # 1=high, 2=medium, 3=low
    tags: List[str] = None
    
    def __post_init__(self):
        if self.tags is None:
            self.tags = []


class ThreatScoringValidator:
    """
    Validates threat scoring consistency using test vectors.
    Provides test datasets with expected outcomes.
    """
    
    def __init__(self):
        self.test_vectors = []
        self.validation_results = []
        self.orchestrator = None
        self._initialize_test_vectors()
    
    def _initialize_test_vectors(self):
        """Initialize comprehensive test vectors."""
        
        # Phishing email test vectors
        self.test_vectors.extend([
            TestVector(
                id="phish_001",
                name="Classic Banking Phishing",
                description="Typical banking phishing with urgency and credential harvesting",
                test_type=TestVectorType.PHISHING_EMAIL,
                input_data={
                    "headers": {
                        "from": "security@bank-alerts.com",
                        "subject": "URGENT: Your account will be suspended in 24 hours",
                        "to": "user@example.com"
                    },
                    "text_content": """
                    URGENT SECURITY ALERT
                    
                    Your account has been compromised and will be suspended in 24 hours.
                    Please verify your account immediately by clicking the link below:
                    
                    https://secure-bank-verification.com/verify?token=abc123
                    
                    Failure to verify will result in permanent account closure.
                    """,
                    "links": ["https://secure-bank-verification.com/verify?token=abc123"],
                    "attachments": []
                },
                expected_outcome=ExpectedOutcome(
                    threat_score_min=0.7,
                    threat_score_max=1.0,
                    threat_level="high",
                    should_contain_indicators=["urgency_pressure_tactics", "credential_harvesting"],
                    should_not_contain_indicators=["legitimate_sender"],
                    confidence_threshold=0.8,
                    verdict_pattern=r"(HIGH THREAT|CRITICAL THREAT|malicious)"
                ),
                priority=1,
                tags=["phishing", "banking", "urgency"]
            ),
            
            TestVector(
                id="phish_002", 
                name="Microsoft 365 Phishing",
                description="Office 365 credential harvesting with redirect chain",
                test_type=TestVectorType.PHISHING_EMAIL,
                input_data={
                    "headers": {
                        "from": "no-reply@microsoft-security.net",
                        "subject": "Sign-in attempt blocked",
                        "to": "user@company.com"
                    },
                    "text_content": """
                    Microsoft Security Alert
                    
                    We blocked a sign-in attempt to your Microsoft account.
                    If this was you, please verify your identity:
                    
                    https://bit.ly/msft-verify-2023
                    
                    If you didn't attempt to sign in, your account may be compromised.
                    """,
                    "links": ["https://bit.ly/msft-verify-2023"],
                    "attachments": []
                },
                expected_outcome=ExpectedOutcome(
                    threat_score_min=0.6,
                    threat_score_max=1.0,
                    threat_level="high",
                    should_contain_indicators=["brand_impersonation", "url_shortener"],
                    should_not_contain_indicators=["legitimate_domain"],
                    confidence_threshold=0.7,
                    verdict_pattern=r"(HIGH THREAT|MEDIUM THREAT|suspicious|malicious)"
                ),
                priority=1,
                tags=["phishing", "microsoft", "redirect"]
            ),
            
            TestVector(
                id="phish_003",
                name="CEO Fraud / BEC",
                description="Business Email Compromise with urgent financial request",
                test_type=TestVectorType.PHISHING_EMAIL,
                input_data={
                    "headers": {
                        "from": "ceo@company-mail.com",
                        "subject": "Urgent: Wire Transfer Required",
                        "to": "finance@company.com"
                    },
                    "text_content": """
                    I need you to process an urgent wire transfer today.
                    
                    Amount: $45,000
                    To: Global Suppliers LLC
                    Account: 123456789
                    Routing: 987654321
                    
                    This is confidential and time-sensitive. Please handle immediately.
                    
                    Thanks,
                    John Smith, CEO
                    """,
                    "links": [],
                    "attachments": []
                },
                expected_outcome=ExpectedOutcome(
                    threat_score_min=0.5,
                    threat_score_max=0.9,
                    threat_level="medium",
                    should_contain_indicators=["urgency", "financial_request", "social_engineering"],
                    should_not_contain_indicators=["legitimate_sender"],
                    confidence_threshold=0.6,
                    verdict_pattern=r"(MEDIUM THREAT|HIGH THREAT|suspicious)"
                ),
                priority=1,
                tags=["bec", "ceo_fraud", "financial"]
            )
        ])
        
        # Legitimate email test vectors
        self.test_vectors.extend([
            TestVector(
                id="legit_001",
                name="Legitimate Newsletter",
                description="Standard company newsletter with proper branding",
                test_type=TestVectorType.LEGITIMATE_EMAIL,
                input_data={
                    "headers": {
                        "from": "newsletter@company.com",
                        "subject": "Monthly Product Updates - March 2024",
                        "to": "subscriber@example.com"
                    },
                    "text_content": """
                    Hello valued customer,
                    
                    Here are our latest product updates for March:
                    
                    - New dashboard features
                    - Performance improvements
                    - Security updates
                    
                    Visit our website for more details: https://company.com/updates
                    
                    Unsubscribe: https://company.com/unsubscribe?token=xyz789
                    """,
                    "links": ["https://company.com/updates", "https://company.com/unsubscribe?token=xyz789"],
                    "attachments": []
                },
                expected_outcome=ExpectedOutcome(
                    threat_score_min=0.0,
                    threat_score_max=0.3,
                    threat_level="safe",
                    should_contain_indicators=[],
                    should_not_contain_indicators=["urgency", "credential_harvesting", "suspicious"],
                    confidence_threshold=0.7,
                    verdict_pattern=r"(SAFE|LOW THREAT|safe)"
                ),
                priority=2,
                tags=["legitimate", "newsletter"]
            ),
            
            TestVector(
                id="legit_002",
                name="Legitimate Password Reset",
                description="Proper password reset from known service",
                test_type=TestVectorType.LEGITIMATE_EMAIL,
                input_data={
                    "headers": {
                        "from": "noreply@github.com",
                        "subject": "Reset your GitHub password",
                        "to": "user@example.com"
                    },
                    "text_content": """
                    Hi there,
                    
                    You recently requested a password reset for your GitHub account.
                    Click the link below to reset your password:
                    
                    https://github.com/password/reset?token=abcd1234
                    
                    This link will expire in 1 hour. If you didn't request this, ignore this email.
                    
                    Thanks,
                    The GitHub Team
                    """,
                    "links": ["https://github.com/password/reset?token=abcd1234"],
                    "attachments": []
                },
                expected_outcome=ExpectedOutcome(
                    threat_score_min=0.0,
                    threat_score_max=0.4,
                    threat_level="safe",
                    should_contain_indicators=[],
                    should_not_contain_indicators=["phishing", "urgency_pressure", "suspicious"],
                    confidence_threshold=0.8,
                    verdict_pattern=r"(SAFE|LOW THREAT|safe)"
                ),
                priority=2,
                tags=["legitimate", "password_reset", "github"]
            )
        ])
        
        # URL test vectors
        self.test_vectors.extend([
            TestVector(
                id="url_001",
                name="Malicious URL with Suspicious TLD",
                description="URL with suspicious TLD and typosquatting",
                test_type=TestVectorType.MALICIOUS_URL,
                input_data={
                    "url": "https://gmai1.tk/login"
                },
                expected_outcome=ExpectedOutcome(
                    threat_score_min=0.6,
                    threat_score_max=1.0,
                    threat_level="high",
                    should_contain_indicators=["suspicious_tld", "typosquatting"],
                    should_not_contain_indicators=["legitimate_domain"],
                    confidence_threshold=0.7,
                    verdict_pattern=r"(malicious|suspicious)"
                ),
                priority=1,
                tags=["url", "typosquatting", "suspicious_tld"]
            ),
            
            TestVector(
                id="url_002",
                name="Legitimate Google URL",
                description="Standard Google search URL",
                test_type=TestVectorType.SAFE_URL,
                input_data={
                    "url": "https://www.google.com/search?q=python+tutorial"
                },
                expected_outcome=ExpectedOutcome(
                    threat_score_min=0.0,
                    threat_score_max=0.2,
                    threat_level="safe",
                    should_contain_indicators=[],
                    should_not_contain_indicators=["malicious", "suspicious", "redirect"],
                    confidence_threshold=0.8,
                    verdict_pattern=r"(safe|SAFE)"
                ),
                priority=2,
                tags=["url", "legitimate", "google"]
            ),
            
            TestVector(
                id="redirect_001",
                name="Suspicious Redirect Chain",
                description="URL with multiple redirects ending at phishing site",
                test_type=TestVectorType.SUSPICIOUS_REDIRECT,
                input_data={
                    "url": "https://bit.ly/bank-security-check"
                },
                expected_outcome=ExpectedOutcome(
                    threat_score_min=0.4,
                    threat_score_max=0.9,
                    threat_level="medium",
                    should_contain_indicators=["url_shortener", "redirect"],
                    should_not_contain_indicators=["safe"],
                    confidence_threshold=0.6,
                    verdict_pattern=r"(suspicious|malicious)"
                ),
                priority=1,
                tags=["redirect", "url_shortener", "suspicious"]
            )
        ])
        
        # IP reputation test vectors
        self.test_vectors.extend([
            TestVector(
                id="ip_001",
                name="Known Malicious IP",
                description="IP address with high abuse confidence",
                test_type=TestVectorType.IP_REPUTATION,
                input_data={
                    "ip": "185.220.101.42"  # Example known bad IP
                },
                expected_outcome=ExpectedOutcome(
                    threat_score_min=0.7,
                    threat_score_max=1.0,
                    threat_level="high",
                    should_contain_indicators=["high_abuse_confidence", "multiple_abuse_reports"],
                    should_not_contain_indicators=["whitelisted"],
                    confidence_threshold=0.8,
                    verdict_pattern=r"(malicious)"
                ),
                priority=1,
                tags=["ip", "malicious", "abuse"]
            ),
            
            TestVector(
                id="ip_002", 
                name="Google DNS IP",
                description="Google's public DNS server",
                test_type=TestVectorType.IP_REPUTATION,
                input_data={
                    "ip": "8.8.8.8"
                },
                expected_outcome=ExpectedOutcome(
                    threat_score_min=0.0,
                    threat_score_max=0.1,
                    threat_level="safe",
                    should_contain_indicators=[],
                    should_not_contain_indicators=["abuse", "malicious"],
                    confidence_threshold=0.9,
                    verdict_pattern=r"(safe)"
                ),
                priority=2,
                tags=["ip", "legitimate", "google"]
            )
        ])
        
        logger.info(f"Initialized {len(self.test_vectors)} test vectors")
    
    async def run_validation_suite(
        self, 
        test_ids: Optional[List[str]] = None,
        test_types: Optional[List[TestVectorType]] = None,
        priority_threshold: int = 3
    ) -> Dict[str, Any]:
        """
        Run comprehensive validation suite.
        
        Args:
            test_ids: Specific test IDs to run (if None, runs all)
            test_types: Specific test types to run (if None, runs all types)
            priority_threshold: Only run tests with priority <= threshold
            
        Returns:
            Validation results with metrics and detailed findings
        """
        
        if self.orchestrator is None:
            self.orchestrator = create_real_threat_orchestrator()
            await self.orchestrator.initialize()
        
        # Filter test vectors
        vectors_to_run = []
        for vector in self.test_vectors:
            # Filter by ID
            if test_ids and vector.id not in test_ids:
                continue
            
            # Filter by type
            if test_types and vector.test_type not in test_types:
                continue
            
            # Filter by priority
            if vector.priority > priority_threshold:
                continue
            
            vectors_to_run.append(vector)
        
        logger.info(f"Running validation on {len(vectors_to_run)} test vectors")
        
        # Run tests
        results = []
        start_time = time.time()
        
        for i, vector in enumerate(vectors_to_run):
            logger.info(f"Running test {i+1}/{len(vectors_to_run)}: {vector.id}")
            
            try:
                result = await self._run_single_test(vector)
                results.append(result)
                
                # Delay between tests
                await asyncio.sleep(1)
                
            except Exception as e:
                logger.error(f"Test {vector.id} failed: {e}")
                results.append({
                    'test_id': vector.id,
                    'passed': False,
                    'error': str(e),
                    'execution_time': 0
                })
        
        # Calculate metrics
        metrics = self._calculate_validation_metrics(results, time.time() - start_time)
        
        # Generate report
        report = {
            'validation_summary': metrics,
            'test_results': results,
            'timestamp': time.time(),
            'total_execution_time': time.time() - start_time
        }
        
        logger.info(f"Validation completed: {metrics['pass_rate']:.1%} pass rate")
        return report
    
    async def _run_single_test(self, vector: TestVector) -> Dict[str, Any]:
        """Run a single test vector and validate results."""
        
        start_time = time.time()
        
        try:
            # Execute analysis based on test type
            if vector.test_type in [TestVectorType.PHISHING_EMAIL, TestVectorType.LEGITIMATE_EMAIL]:
                analysis_result = await self.orchestrator.analyze_email_comprehensive(vector.input_data)
            else:
                # For URL and IP tests, create minimal email wrapper
                email_data = {
                    "headers": {"subject": "Test", "from": "test@test.com"},
                    "text_content": f"Test content with {vector.input_data}",
                    "links": [vector.input_data.get('url')] if 'url' in vector.input_data else [],
                    "ips": [vector.input_data.get('ip')] if 'ip' in vector.input_data else []
                }
                analysis_result = await self.orchestrator.analyze_email_comprehensive(email_data)
            
            # Validate result against expected outcome
            validation_result = self._validate_result(analysis_result, vector.expected_outcome)
            
            execution_time = time.time() - start_time
            
            return {
                'test_id': vector.id,
                'test_name': vector.name,
                'test_type': vector.test_type.value,
                'passed': validation_result['passed'],
                'score_actual': analysis_result.get('threat_score', 0.0),
                'score_expected_range': [vector.expected_outcome.threat_score_min, vector.expected_outcome.threat_score_max],
                'confidence_actual': analysis_result.get('confidence', 0.0),
                'confidence_expected': vector.expected_outcome.confidence_threshold,
                'verdict_actual': analysis_result.get('verdict', 'unknown'),
                'verdict_expected_pattern': vector.expected_outcome.verdict_pattern,
                'indicators_found': analysis_result.get('indicators', []),
                'indicators_expected': vector.expected_outcome.should_contain_indicators,
                'validation_details': validation_result,
                'execution_time': execution_time,
                'analysis_result': analysis_result
            }
            
        except Exception as e:
            logger.error(f"Test execution failed for {vector.id}: {e}")
            return {
                'test_id': vector.id,
                'test_name': vector.name,
                'test_type': vector.test_type.value,
                'passed': False,
                'error': str(e),
                'execution_time': time.time() - start_time
            }
    
    def _validate_result(self, analysis_result: Dict[str, Any], expected: ExpectedOutcome) -> Dict[str, Any]:
        """Validate analysis result against expected outcome."""
        
        validation = {
            'passed': True,
            'failures': [],
            'warnings': [],
            'score': 1.0
        }
        
        # Validate threat score range
        actual_score = analysis_result.get('threat_score', 0.0)
        if not (expected.threat_score_min <= actual_score <= expected.threat_score_max):
            validation['passed'] = False
            validation['failures'].append(
                f"Threat score {actual_score} not in expected range [{expected.threat_score_min}, {expected.threat_score_max}]"
            )
            validation['score'] *= 0.5
        
        # Validate confidence threshold
        actual_confidence = analysis_result.get('confidence', 0.0)
        if actual_confidence < expected.confidence_threshold:
            validation['warnings'].append(
                f"Confidence {actual_confidence} below threshold {expected.confidence_threshold}"
            )
            validation['score'] *= 0.8
        
        # Validate verdict pattern
        actual_verdict = analysis_result.get('verdict', '')
        import re
        if not re.search(expected.verdict_pattern, actual_verdict, re.IGNORECASE):
            validation['passed'] = False
            validation['failures'].append(
                f"Verdict '{actual_verdict}' doesn't match pattern '{expected.verdict_pattern}'"
            )
            validation['score'] *= 0.7
        
        # Validate required indicators
        actual_indicators = analysis_result.get('indicators', [])
        actual_indicators_text = ' '.join(str(ind).lower() for ind in actual_indicators)
        
        missing_indicators = []
        for required in expected.should_contain_indicators:
            if required.lower() not in actual_indicators_text:
                missing_indicators.append(required)
        
        if missing_indicators:
            validation['warnings'].append(f"Missing expected indicators: {missing_indicators}")
            validation['score'] *= 0.9
        
        # Validate forbidden indicators
        forbidden_found = []
        for forbidden in expected.should_not_contain_indicators:
            if forbidden.lower() in actual_indicators_text:
                forbidden_found.append(forbidden)
        
        if forbidden_found:
            validation['passed'] = False
            validation['failures'].append(f"Found forbidden indicators: {forbidden_found}")
            validation['score'] *= 0.6
        
        return validation
    
    def _calculate_validation_metrics(self, results: List[Dict[str, Any]], total_time: float) -> Dict[str, Any]:
        """Calculate validation metrics from test results."""
        
        total_tests = len(results)
        passed_tests = sum(1 for r in results if r.get('passed', False))
        failed_tests = total_tests - passed_tests
        
        # Calculate scores
        scores = [r.get('validation_details', {}).get('score', 0.0) for r in results if 'validation_details' in r]
        avg_validation_score = sum(scores) / len(scores) if scores else 0.0
        
        # Group by test type
        type_stats = {}
        for result in results:
            test_type = result.get('test_type', 'unknown')
            if test_type not in type_stats:
                type_stats[test_type] = {'total': 0, 'passed': 0}
            type_stats[test_type]['total'] += 1
            if result.get('passed', False):
                type_stats[test_type]['passed'] += 1
        
        # Calculate execution time stats
        execution_times = [r.get('execution_time', 0) for r in results]
        avg_execution_time = sum(execution_times) / len(execution_times) if execution_times else 0
        
        return {
            'total_tests': total_tests,
            'passed_tests': passed_tests,
            'failed_tests': failed_tests,
            'pass_rate': passed_tests / total_tests if total_tests > 0 else 0.0,
            'average_validation_score': avg_validation_score,
            'total_execution_time': total_time,
            'average_test_execution_time': avg_execution_time,
            'type_statistics': type_stats,
            'performance_grade': self._calculate_performance_grade(passed_tests / total_tests if total_tests > 0 else 0.0)
        }
    
    def _calculate_performance_grade(self, pass_rate: float) -> str:
        """Calculate performance grade based on pass rate."""
        if pass_rate >= 0.95:
            return "A+"
        elif pass_rate >= 0.90:
            return "A"
        elif pass_rate >= 0.85:
            return "B+"
        elif pass_rate >= 0.80:
            return "B"
        elif pass_rate >= 0.75:
            return "C+"
        elif pass_rate >= 0.70:
            return "C"
        elif pass_rate >= 0.60:
            return "D"
        else:
            return "F"
    
    def export_test_vectors(self, filename: str) -> None:
        """Export test vectors to JSON file."""
        export_data = {
            'test_vectors': [asdict(vector) for vector in self.test_vectors],
            'export_timestamp': time.time(),
            'total_vectors': len(self.test_vectors)
        }
        
        with open(filename, 'w') as f:
            json.dump(export_data, f, indent=2, default=str)
        
        logger.info(f"Exported {len(self.test_vectors)} test vectors to {filename}")
    
    def import_test_vectors(self, filename: str) -> None:
        """Import test vectors from JSON file."""
        with open(filename, 'r') as f:
            import_data = json.load(f)
        
        imported_vectors = []
        for vector_data in import_data.get('test_vectors', []):
            # Convert back to objects
            vector_data['test_type'] = TestVectorType(vector_data['test_type'])
            
            expected = vector_data['expected_outcome']
            vector_data['expected_outcome'] = ExpectedOutcome(**expected)
            
            vector = TestVector(**vector_data)
            imported_vectors.append(vector)
        
        self.test_vectors.extend(imported_vectors)
        logger.info(f"Imported {len(imported_vectors)} test vectors from {filename}")
    
    def get_test_vector_summary(self) -> Dict[str, Any]:
        """Get summary statistics of available test vectors."""
        
        type_counts = {}
        priority_counts = {}
        tag_counts = {}
        
        for vector in self.test_vectors:
            # Count by type
            test_type = vector.test_type.value
            type_counts[test_type] = type_counts.get(test_type, 0) + 1
            
            # Count by priority
            priority = vector.priority
            priority_counts[priority] = priority_counts.get(priority, 0) + 1
            
            # Count by tags
            for tag in vector.tags:
                tag_counts[tag] = tag_counts.get(tag, 0) + 1
        
        return {
            'total_vectors': len(self.test_vectors),
            'by_type': type_counts,
            'by_priority': priority_counts,
            'by_tags': dict(sorted(tag_counts.items(), key=lambda x: x[1], reverse=True)[:10]),  # Top 10 tags
            'coverage': {
                'phishing_vectors': sum(1 for v in self.test_vectors if 'phishing' in v.tags),
                'legitimate_vectors': sum(1 for v in self.test_vectors if 'legitimate' in v.tags),
                'url_vectors': sum(1 for v in self.test_vectors if 'url' in v.tags),
                'ip_vectors': sum(1 for v in self.test_vectors if 'ip' in v.tags)
            }
        }


# Factory function
def create_threat_scoring_validator() -> ThreatScoringValidator:
    """Create ThreatScoringValidator instance."""
    return ThreatScoringValidator()


# Convenience function for quick validation
async def run_quick_validation() -> Dict[str, Any]:
    """Run quick validation with high-priority test vectors."""
    validator = create_threat_scoring_validator()
    return await validator.run_validation_suite(priority_threshold=1)
