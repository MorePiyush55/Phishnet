"""
Comprehensive Acceptance Tests for PhishNet
Create test dataset with known phishing emails and expected verdicts/scores
Ensure results are within expected thresholds
Test against known phishing datasets and validate accuracy
"""

import pytest
import asyncio
import json
import time
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass
from unittest.mock import Mock, patch, AsyncMock
from datetime import datetime
import statistics

# Core imports
from app.orchestrator.main import PhishNetOrchestrator
from app.schemas.threat_response import ThreatResult, ThreatLevel
from app.ml.threat_aggregator import ThreatAggregator


@dataclass
class KnownTestCase:
    """A known test case with expected results"""
    id: str
    category: str  # 'legitimate', 'phishing', 'suspicious', 'malware'
    subject: str
    sender: str
    body: str
    links: List[str]
    expected_threat_level: ThreatLevel
    expected_score_range: Tuple[float, float]  # (min, max)
    description: str
    source: str  # Source of the test case


class PhishingDataset:
    """Known phishing dataset for testing"""
    
    def __init__(self):
        self.test_cases = self._load_known_cases()
    
    def _load_known_cases(self) -> List[KnownTestCase]:
        """Load known test cases"""
        
        return [
            # LEGITIMATE EMAILS
            KnownTestCase(
                id="legit_001",
                category="legitimate",
                subject="Weekly Team Meeting - Agenda",
                sender="manager@company.com",
                body="""Hi Team,

Our weekly team meeting is scheduled for Thursday at 2 PM.

Agenda:
1. Project updates
2. Q3 planning
3. Team announcements

Please review the attached documents before the meeting.

Best regards,
Sarah""",
                links=["https://company.com/calendar/meeting/12345"],
                expected_threat_level=ThreatLevel.LOW,
                expected_score_range=(0.0, 0.3),
                description="Legitimate corporate meeting invitation",
                source="Internal dataset"
            ),
            
            KnownTestCase(
                id="legit_002",
                category="legitimate",
                subject="Your Order #12345 Has Shipped",
                sender="orders@amazon.com",
                body="""Thank you for your order!

Your order #12345 has been shipped and is on its way.

Tracking number: 1Z999AA1234567890
Expected delivery: December 15, 2023

Track your package: https://amazon.com/tracking/1Z999AA1234567890

Thanks for shopping with us!""",
                links=["https://amazon.com/tracking/1Z999AA1234567890"],
                expected_threat_level=ThreatLevel.LOW,
                expected_score_range=(0.0, 0.2),
                description="Legitimate shipping notification",
                source="E-commerce dataset"
            ),
            
            # PHISHING EMAILS
            KnownTestCase(
                id="phish_001",
                category="phishing",
                subject="URGENT: Your Bank Account Has Been Suspended",
                sender="security@fake-bankofamerica.com",
                body="""URGENT SECURITY ALERT

Your Bank of America account has been suspended due to suspicious activity.

To reactivate your account immediately:
1. Click here: https://fake-bankofamerica.secure-login.ru/urgent
2. Verify your identity
3. Update your security information

Failure to act within 24 hours will result in permanent account closure.

Bank of America Security Team""",
                links=["https://fake-bankofamerica.secure-login.ru/urgent"],
                expected_threat_level=ThreatLevel.HIGH,
                expected_score_range=(0.8, 1.0),
                description="Classic banking phishing with urgent language",
                source="PhishTank verified"
            ),
            
            KnownTestCase(
                id="phish_002",
                category="phishing",
                subject="Your PayPal Account Needs Verification",
                sender="service@paypal-security.info",
                body="""Dear PayPal Customer,

We've detected unusual activity on your account.

Your account is temporarily limited. To remove limitations:

Click here to verify: https://paypal-verification.secure-site.tk/verify

You have 48 hours to complete verification or your account will be permanently suspended.

PayPal Security Team""",
                links=["https://paypal-verification.secure-site.tk/verify"],
                expected_threat_level=ThreatLevel.HIGH,
                expected_score_range=(0.85, 1.0),
                description="PayPal phishing with domain spoofing",
                source="Anti-Phishing Working Group"
            ),
            
            KnownTestCase(
                id="phish_003",
                category="phishing",
                subject="Action Required: Microsoft Account Security Alert",
                sender="microsoftsecurity@outlook-security.org",
                body="""Microsoft Security Alert

Someone tried to sign in to your Microsoft account from a new device.

Device: iPhone 12 Pro
Location: Nigeria
Date: December 10, 2023

If this wasn't you, secure your account now:
https://microsoft-account-security.verification-site.ml/secure

This link expires in 6 hours for your security.

Microsoft Account Team""",
                links=["https://microsoft-account-security.verification-site.ml/secure"],
                expected_threat_level=ThreatLevel.HIGH,
                expected_score_range=(0.8, 0.95),
                description="Microsoft account phishing with geographic indicators",
                source="Security research"
            ),
            
            # SUSPICIOUS EMAILS
            KnownTestCase(
                id="suspicious_001",
                category="suspicious",
                subject="Congratulations! You've Won $1,000,000!",
                sender="lottery@winnings-international.biz",
                body="""CONGRATULATIONS!

You have been selected as a winner in our international lottery!

Prize: $1,000,000 USD
Reference: WIN/2023/12345

To claim your prize, reply with:
- Full name
- Address
- Phone number
- Copy of ID

Contact our claims agent: agent@winnings-international.biz

Claim within 14 days or forfeit your winnings!""",
                links=["mailto:agent@winnings-international.biz"],
                expected_threat_level=ThreatLevel.MEDIUM,
                expected_score_range=(0.6, 0.8),
                description="Lottery scam with personal information request",
                source="Spam dataset"
            ),
            
            # MALWARE EMAILS
            KnownTestCase(
                id="malware_001",
                category="malware",
                subject="Invoice #2023-12345 - Payment Overdue",
                sender="billing@company-invoices.download",
                body="""Invoice Overdue Notice

Your payment for invoice #2023-12345 is now 30 days overdue.

Amount due: $2,847.50
Due date: November 15, 2023

Download invoice: https://company-invoices.download/invoice.exe

Please remit payment immediately to avoid legal action.

Accounts Receivable Department""",
                links=["https://company-invoices.download/invoice.exe"],
                expected_threat_level=ThreatLevel.HIGH,
                expected_score_range=(0.9, 1.0),
                description="Malware distribution via fake invoice",
                source="Malware research"
            ),
            
            # REDIRECT CHAINS
            KnownTestCase(
                id="redirect_001",
                category="phishing",
                subject="Click Here for Special Offer!",
                sender="offers@deals-today.com",
                body="""Limited Time Offer!

Get 90% off premium software today only!

Click here: https://bit.ly/special-offer-2023

Hurry - only 100 licenses available!""",
                links=["https://bit.ly/special-offer-2023"],  # This would redirect through multiple hops
                expected_threat_level=ThreatLevel.MEDIUM,
                expected_score_range=(0.5, 0.8),
                description="Phishing via redirect chain with URL shortener",
                source="URL analysis dataset"
            ),
        ]
    
    def get_by_category(self, category: str) -> List[KnownTestCase]:
        """Get test cases by category"""
        return [case for case in self.test_cases if case.category == category]
    
    def get_all(self) -> List[KnownTestCase]:
        """Get all test cases"""
        return self.test_cases


@dataclass
class AcceptanceTestResults:
    """Results from acceptance testing"""
    total_cases: int = 0
    correct_predictions: int = 0
    false_positives: int = 0
    false_negatives: int = 0
    score_variance_violations: int = 0
    average_processing_time: float = 0.0
    results_by_category: Dict[str, Dict[str, int]] = None
    
    def __post_init__(self):
        if self.results_by_category is None:
            self.results_by_category = {}
    
    def accuracy(self) -> float:
        return (self.correct_predictions / self.total_cases) if self.total_cases > 0 else 0.0
    
    def precision(self) -> float:
        true_positives = self.correct_predictions - self.false_negatives
        predicted_positives = true_positives + self.false_positives
        return (true_positives / predicted_positives) if predicted_positives > 0 else 0.0
    
    def recall(self) -> float:
        true_positives = self.correct_predictions - self.false_negatives
        actual_positives = true_positives + self.false_negatives
        return (true_positives / actual_positives) if actual_positives > 0 else 0.0
    
    def f1_score(self) -> float:
        p = self.precision()
        r = self.recall()
        return (2 * p * r / (p + r)) if (p + r) > 0 else 0.0


class AcceptanceTestRunner:
    """Run acceptance tests against known datasets"""
    
    def __init__(self):
        self.orchestrator = PhishNetOrchestrator()
        self.dataset = PhishingDataset()
        self.results = AcceptanceTestResults()
    
    async def run_full_acceptance_suite(self) -> AcceptanceTestResults:
        """Run complete acceptance test suite"""
        
        print("Starting PhishNet Acceptance Test Suite...")
        print(f"Testing against {len(self.dataset.get_all())} known cases")
        
        # Reset results
        self.results = AcceptanceTestResults()
        self.results.results_by_category = {}
        
        # Track timing
        start_time = time.time()
        processing_times = []
        
        # Test each case
        for test_case in self.dataset.get_all():
            case_start = time.time()
            
            print(f"\nTesting case: {test_case.id} ({test_case.category})")
            
            # Run the test
            result = await self._test_single_case(test_case)
            
            # Record timing
            case_time = time.time() - case_start
            processing_times.append(case_time)
            
            # Update results
            self._update_results(test_case, result)
        
        # Finalize metrics
        self.results.total_cases = len(self.dataset.get_all())
        self.results.average_processing_time = statistics.mean(processing_times)
        
        # Print summary
        self._print_results_summary()
        
        return self.results
    
    async def _test_single_case(self, test_case: KnownTestCase) -> Optional[ThreatResult]:
        """Test a single case"""
        
        # Mock external API responses for consistency
        with patch('app.integrations.virustotal.VirusTotalAdapter.scan_url') as mock_vt, \
             patch('app.integrations.gemini.GeminiAdapter.analyze_content') as mock_gemini, \
             patch('app.integrations.abuseipdb.AbuseIPDBAdapter.check_ip') as mock_abuse:
            
            # Configure mocks based on test case category
            if test_case.category == "phishing":
                mock_vt.return_value = Mock(
                    scan_id=f"vt_{test_case.id}",
                    positives=25,  # High detection
                    total=70,
                    permalink=f"https://virustotal.com/{test_case.id}"
                )
                mock_gemini.return_value = {
                    'threat_probability': 0.9,
                    'confidence': 0.95,
                    'reasoning': 'Clear phishing indicators detected',
                    'risk_factors': ['urgent_language', 'credential_request', 'domain_spoofing']
                }
                mock_abuse.return_value = Mock(
                    ip_address="203.0.113.100",
                    abuse_confidence=75,
                    total_reports=30
                )
            
            elif test_case.category == "legitimate":
                mock_vt.return_value = Mock(
                    scan_id=f"vt_{test_case.id}",
                    positives=0,  # No detection
                    total=70,
                    permalink=f"https://virustotal.com/{test_case.id}"
                )
                mock_gemini.return_value = {
                    'threat_probability': 0.1,
                    'confidence': 0.8,
                    'reasoning': 'Appears to be legitimate communication',
                    'risk_factors': []
                }
                mock_abuse.return_value = Mock(
                    ip_address="1.2.3.4",
                    abuse_confidence=0,
                    total_reports=0
                )
            
            elif test_case.category == "suspicious":
                mock_vt.return_value = Mock(
                    scan_id=f"vt_{test_case.id}",
                    positives=5,  # Some detection
                    total=70,
                    permalink=f"https://virustotal.com/{test_case.id}"
                )
                mock_gemini.return_value = {
                    'threat_probability': 0.6,
                    'confidence': 0.7,
                    'reasoning': 'Suspicious patterns detected',
                    'risk_factors': ['money_request', 'urgency']
                }
                mock_abuse.return_value = Mock(
                    ip_address="198.51.100.50",
                    abuse_confidence=25,
                    total_reports=5
                )
            
            elif test_case.category == "malware":
                mock_vt.return_value = Mock(
                    scan_id=f"vt_{test_case.id}",
                    positives=45,  # Very high detection
                    total=70,
                    permalink=f"https://virustotal.com/{test_case.id}"
                )
                mock_gemini.return_value = {
                    'threat_probability': 0.95,
                    'confidence': 0.98,
                    'reasoning': 'High probability malware distribution',
                    'risk_factors': ['executable_download', 'fake_invoice', 'suspicious_domain']
                }
                mock_abuse.return_value = Mock(
                    ip_address="203.0.113.200",
                    abuse_confidence=90,
                    total_reports=100
                )
            
            try:
                # Run the scan
                result = await self.orchestrator.scan_email(
                    user_id=f"acceptance_test_user",
                    email_id=test_case.id,
                    subject=test_case.subject,
                    sender=test_case.sender,
                    body=test_case.body,
                    links=test_case.links
                )
                
                return result
                
            except Exception as e:
                print(f"Error testing case {test_case.id}: {e}")
                return None
    
    def _update_results(self, test_case: KnownTestCase, result: Optional[ThreatResult]):
        """Update test results"""
        
        if result is None:
            return
        
        # Initialize category tracking
        if test_case.category not in self.results.results_by_category:
            self.results.results_by_category[test_case.category] = {
                'total': 0,
                'correct': 0,
                'false_positive': 0,
                'false_negative': 0
            }
        
        category_results = self.results.results_by_category[test_case.category]
        category_results['total'] += 1
        
        # Check threat level prediction
        predicted_level = result.overall_threat_level
        expected_level = test_case.expected_threat_level
        
        is_correct = predicted_level == expected_level
        
        if is_correct:
            self.results.correct_predictions += 1
            category_results['correct'] += 1
        else:
            # Determine type of error
            if expected_level == ThreatLevel.LOW and predicted_level in [ThreatLevel.MEDIUM, ThreatLevel.HIGH]:
                self.results.false_positives += 1
                category_results['false_positive'] += 1
            elif expected_level in [ThreatLevel.MEDIUM, ThreatLevel.HIGH] and predicted_level == ThreatLevel.LOW:
                self.results.false_negatives += 1
                category_results['false_negative'] += 1
        
        # Check score range
        expected_min, expected_max = test_case.expected_score_range
        actual_score = result.confidence_score
        
        if not (expected_min <= actual_score <= expected_max):
            self.results.score_variance_violations += 1
        
        print(f"  Expected: {expected_level.value} ({expected_min}-{expected_max})")
        print(f"  Actual: {predicted_level.value} ({actual_score:.3f})")
        print(f"  Result: {'✓ CORRECT' if is_correct else '✗ INCORRECT'}")
    
    def _print_results_summary(self):
        """Print comprehensive results summary"""
        
        print("\n" + "="*80)
        print("PHISHNET ACCEPTANCE TEST RESULTS")
        print("="*80)
        
        print(f"\nOVERALL METRICS:")
        print(f"  Total Cases: {self.results.total_cases}")
        print(f"  Correct Predictions: {self.results.correct_predictions}")
        print(f"  Accuracy: {self.results.accuracy():.2%}")
        print(f"  Precision: {self.results.precision():.2%}")
        print(f"  Recall: {self.results.recall():.2%}")
        print(f"  F1 Score: {self.results.f1_score():.2%}")
        print(f"  Avg Processing Time: {self.results.average_processing_time:.2f}s")
        
        print(f"\nERROR ANALYSIS:")
        print(f"  False Positives: {self.results.false_positives}")
        print(f"  False Negatives: {self.results.false_negatives}")
        print(f"  Score Variance Violations: {self.results.score_variance_violations}")
        
        print(f"\nRESULTS BY CATEGORY:")
        for category, results in self.results.results_by_category.items():
            accuracy = (results['correct'] / results['total']) if results['total'] > 0 else 0
            print(f"  {category.upper()}:")
            print(f"    Total: {results['total']}")
            print(f"    Correct: {results['correct']}")
            print(f"    Accuracy: {accuracy:.2%}")
            print(f"    False Positives: {results['false_positive']}")
            print(f"    False Negatives: {results['false_negative']}")


class TestAcceptanceValidation:
    """Acceptance tests against known datasets"""
    
    def setup_method(self):
        """Set up acceptance testing"""
        self.runner = AcceptanceTestRunner()
    
    @pytest.mark.asyncio
    async def test_known_phishing_detection(self):
        """Test detection of known phishing emails"""
        
        phishing_cases = self.runner.dataset.get_by_category("phishing")
        
        print(f"Testing {len(phishing_cases)} known phishing cases...")
        
        correct = 0
        for case in phishing_cases:
            result = await self.runner._test_single_case(case)
            
            if result and result.overall_threat_level in [ThreatLevel.MEDIUM, ThreatLevel.HIGH]:
                correct += 1
        
        accuracy = correct / len(phishing_cases)
        print(f"Phishing Detection Accuracy: {accuracy:.2%}")
        
        # Assertion: Should detect at least 85% of known phishing
        assert accuracy >= 0.85, f"Phishing detection accuracy too low: {accuracy:.2%}"
    
    @pytest.mark.asyncio
    async def test_legitimate_email_acceptance(self):
        """Test that legitimate emails are not flagged as threats"""
        
        legitimate_cases = self.runner.dataset.get_by_category("legitimate")
        
        print(f"Testing {len(legitimate_cases)} legitimate cases...")
        
        correct = 0
        for case in legitimate_cases:
            result = await self.runner._test_single_case(case)
            
            if result and result.overall_threat_level == ThreatLevel.LOW:
                correct += 1
        
        accuracy = correct / len(legitimate_cases)
        print(f"Legitimate Email Accuracy: {accuracy:.2%}")
        
        # Assertion: Should correctly identify at least 90% of legitimate emails
        assert accuracy >= 0.90, f"Legitimate email accuracy too low: {accuracy:.2%}"
    
    @pytest.mark.asyncio
    async def test_score_consistency_and_determinism(self):
        """Test that scoring is consistent and deterministic"""
        
        test_case = self.runner.dataset.get_all()[0]  # Use first test case
        
        # Run same test multiple times
        scores = []
        for _ in range(5):
            result = await self.runner._test_single_case(test_case)
            if result:
                scores.append(result.confidence_score)
        
        # Check score consistency
        if len(scores) > 1:
            score_variance = statistics.variance(scores)
            max_variance = 0.05  # Maximum allowed variance
            
            print(f"Score Consistency Test:")
            print(f"  Scores: {scores}")
            print(f"  Variance: {score_variance:.4f}")
            print(f"  Max Allowed: {max_variance}")
            
            assert score_variance <= max_variance, f"Score variance too high: {score_variance}"
    
    @pytest.mark.asyncio
    async def test_full_acceptance_suite(self):
        """Run the complete acceptance test suite"""
        
        results = await self.runner.run_full_acceptance_suite()
        
        # Core acceptance criteria
        assert results.accuracy() >= 0.85, f"Overall accuracy too low: {results.accuracy():.2%}"
        assert results.false_positives <= 2, f"Too many false positives: {results.false_positives}"
        assert results.false_negatives <= 1, f"Too many false negatives: {results.false_negatives}"
        assert results.score_variance_violations == 0, f"Score variance violations: {results.score_variance_violations}"
        assert results.average_processing_time <= 10.0, f"Processing too slow: {results.average_processing_time}s"
        
        # Category-specific requirements
        for category, category_results in results.results_by_category.items():
            category_accuracy = (category_results['correct'] / category_results['total']) if category_results['total'] > 0 else 0
            
            if category == "phishing":
                assert category_accuracy >= 0.85, f"Phishing detection accuracy too low: {category_accuracy:.2%}"
            elif category == "legitimate":
                assert category_accuracy >= 0.90, f"Legitimate email accuracy too low: {category_accuracy:.2%}"
            elif category in ["suspicious", "malware"]:
                assert category_accuracy >= 0.80, f"{category} detection accuracy too low: {category_accuracy:.2%}"
    
    @pytest.mark.asyncio
    async def test_performance_requirements(self):
        """Test performance meets requirements"""
        
        # Test single email processing time
        test_case = self.runner.dataset.get_all()[0]
        
        start_time = time.time()
        result = await self.runner._test_single_case(test_case)
        processing_time = time.time() - start_time
        
        print(f"Single Email Processing Time: {processing_time:.2f}s")
        
        # Assertions
        assert result is not None, "Failed to process test email"
        assert processing_time <= 15.0, f"Processing time too slow: {processing_time}s"
    
    @pytest.mark.asyncio
    async def test_edge_cases_and_robustness(self):
        """Test edge cases and system robustness"""
        
        edge_cases = [
            {
                'id': 'edge_empty',
                'subject': '',
                'sender': '',
                'body': '',
                'links': [],
                'description': 'Empty email'
            },
            {
                'id': 'edge_long',
                'subject': 'A' * 1000,
                'sender': 'test@example.com',
                'body': 'B' * 10000,
                'links': [f'https://test{i}.com' for i in range(50)],
                'description': 'Very long email with many links'
            },
            {
                'id': 'edge_unicode',
                'subject': '🚨 URGENT: 账户验证 عاجل',
                'sender': 'test@münchen.de',
                'body': 'Unicode test: 漢字 العربية ñáéíóú',
                'links': ['https://例え.テスト'],
                'description': 'Unicode characters'
            }
        ]
        
        for edge_case in edge_cases:
            print(f"Testing edge case: {edge_case['description']}")
            
            try:
                result = await self.runner.orchestrator.scan_email(
                    user_id="edge_test_user",
                    email_id=edge_case['id'],
                    subject=edge_case['subject'],
                    sender=edge_case['sender'],
                    body=edge_case['body'],
                    links=edge_case['links']
                )
                
                # Should handle gracefully
                assert result is not None, f"Failed to handle edge case: {edge_case['description']}"
                
            except Exception as e:
                pytest.fail(f"Exception on edge case {edge_case['description']}: {e}")


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])
