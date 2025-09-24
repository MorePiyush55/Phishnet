"""
Comprehensive test suite for Deterministic Threat Aggregator - Priority 5
Tests scoring consistency, reproducibility, and explainability.
"""

import asyncio
import pytest
import json
import time
from typing import Dict, Any, List

from app.services.deterministic_threat_aggregator import (
    DeterministicThreatAggregator,
    ThreatCategory,
    ConfidenceLevel,
    ThreatIndicator,
    DeterministicThreatResult
)


class TestDeterministicThreatAggregator:
    """Test suite for deterministic threat aggregator."""
    
    @pytest.fixture
    def aggregator(self):
        """Create aggregator instance for testing."""
        return DeterministicThreatAggregator()
    
    @pytest.fixture
    def sample_phishing_email(self):
        """Sample phishing email data."""
        return {
            "subject": "URGENT: Verify Your Account Now!",
            "sender": "security@amaz0n-verification.com",
            "content": "Your account will be suspended unless you verify immediately. Click here to verify: http://amaz0n-verify.malicious.com/verify",
            "received_at": "2025-09-22T10:00:00Z"
        }
    
    @pytest.fixture
    def sample_phishing_analysis(self):
        """Sample analysis results for phishing email."""
        return {
            "url_analysis": {
                "total_urls": 1,
                "malicious_urls": ["http://amaz0n-verify.malicious.com/verify"],
                "suspicious_urls": [],
                "typosquatting_detected": True,
                "risk_score": 0.9
            },
            "content_analysis": {
                "phishing_indicators": 0.8,
                "phishing_evidence": ["Urgent language", "Account suspension threat"],
                "urgency_score": 0.9,
                "urgency_keywords": ["URGENT", "immediately", "suspended"],
                "credential_harvesting": True,
                "risk_score": 0.85
            },
            "sender_analysis": {
                "spoofing_detected": True,
                "domain_reputation": 0.1,
                "risk_score": 0.7
            },
            "attachment_analysis": {
                "suspicious_files": [],
                "risk_score": 0.0
            }
        }
    
    @pytest.fixture
    def sample_legitimate_email(self):
        """Sample legitimate email data."""
        return {
            "subject": "Weekly Newsletter - Tech Updates",
            "sender": "newsletter@legitimate-tech.com",
            "content": "Hello! Here are this week's tech updates and industry news.",
            "received_at": "2025-09-22T10:00:00Z"
        }
    
    @pytest.fixture
    def sample_legitimate_analysis(self):
        """Sample analysis results for legitimate email."""
        return {
            "url_analysis": {
                "total_urls": 1,
                "malicious_urls": [],
                "suspicious_urls": [],
                "typosquatting_detected": False,
                "risk_score": 0.1
            },
            "content_analysis": {
                "phishing_indicators": 0.0,
                "phishing_evidence": [],
                "urgency_score": 0.0,
                "urgency_keywords": [],
                "credential_harvesting": False,
                "risk_score": 0.05
            },
            "sender_analysis": {
                "spoofing_detected": False,
                "domain_reputation": 0.9,
                "risk_score": 0.1
            },
            "attachment_analysis": {
                "suspicious_files": [],
                "risk_score": 0.0
            }
        }
    
    @pytest.mark.asyncio
    async def test_reproducible_scoring(self, aggregator, sample_phishing_email, sample_phishing_analysis):
        """Test that identical inputs produce identical results."""
        
        # Run analysis multiple times
        results = []
        for i in range(5):
            result = await aggregator.analyze_threat_deterministic(
                sample_phishing_email, sample_phishing_analysis
            )
            results.append(result)
        
        # Verify all results have identical scores
        first_score = results[0].final_score
        for result in results[1:]:
            assert result.final_score == first_score, "Scores should be identical for same input"
        
        # Verify all results have identical hashes
        first_hash = results[0].input_hash
        for result in results[1:]:
            assert result.input_hash == first_hash, "Input hashes should be identical"
        
        # Verify all results have identical threat categories
        first_category = results[0].threat_category
        for result in results[1:]:
            assert result.threat_category == first_category, "Threat categories should be identical"
    
    @pytest.mark.asyncio
    async def test_phishing_detection_accuracy(self, aggregator, sample_phishing_email, sample_phishing_analysis):
        """Test accurate detection of phishing emails."""
        
        result = await aggregator.analyze_threat_deterministic(
            sample_phishing_email, sample_phishing_analysis
        )
        
        # Phishing email should have high threat score
        assert result.final_score >= 0.7, f"Phishing email should have high score, got {result.final_score}"
        
        # Should be categorized as phishing or high threat
        assert result.threat_category in [ThreatCategory.PHISHING, ThreatCategory.SCAM], \
            f"Should be high threat category, got {result.threat_category}"
        
        # Should have reasonable confidence
        assert result.confidence_score >= 0.6, f"Should have decent confidence, got {result.confidence_score}"
        
        # Should detect key indicators
        indicator_names = [ind.name for ind in result.indicators]
        expected_indicators = ["malicious_urls", "phishing_keywords", "credential_harvesting"]
        
        for expected in expected_indicators:
            assert expected in indicator_names, f"Should detect {expected} indicator"
    
    @pytest.mark.asyncio
    async def test_legitimate_email_accuracy(self, aggregator, sample_legitimate_email, sample_legitimate_analysis):
        """Test accurate handling of legitimate emails."""
        
        result = await aggregator.analyze_threat_deterministic(
            sample_legitimate_email, sample_legitimate_analysis
        )
        
        # Legitimate email should have low threat score
        assert result.final_score <= 0.3, f"Legitimate email should have low score, got {result.final_score}"
        
        # Should be categorized as legitimate or low threat
        assert result.threat_category in [ThreatCategory.LEGITIMATE, ThreatCategory.SUSPICIOUS], \
            f"Should be low threat category, got {result.threat_category}"
        
        # Should have minimal indicators
        assert len(result.indicators) <= 2, f"Should have few indicators, got {len(result.indicators)}"
    
    @pytest.mark.asyncio
    async def test_explanation_quality(self, aggregator, sample_phishing_email, sample_phishing_analysis):
        """Test quality and comprehensiveness of explanations."""
        
        result = await aggregator.analyze_threat_deterministic(
            sample_phishing_email, sample_phishing_analysis
        )
        
        # Explanation should be comprehensive
        assert len(result.explanation) > 50, "Explanation should be detailed"
        assert "Score:" in result.explanation, "Should include score in explanation"
        assert result.threat_category.value.upper() in result.explanation, "Should include threat category"
        
        # Should have explanation components
        assert len(result.components) > 0, "Should have explanation components"
        
        # Components should have required fields
        for component in result.components:
            assert component.component, "Component should have name"
            assert 0 <= component.score <= 1, "Component score should be valid"
            assert 0 <= component.weight <= 1, "Component weight should be valid"
            assert component.reasoning, "Component should have reasoning"
    
    @pytest.mark.asyncio
    async def test_confidence_calculation(self, aggregator):
        """Test confidence calculation accuracy."""
        
        # Test high-confidence scenario
        high_conf_analysis = {
            "url_analysis": {
                "malicious_urls": ["http://evil.com", "http://phishing.com"],
                "typosquatting_detected": True,
                "risk_score": 0.95
            },
            "content_analysis": {
                "phishing_indicators": 0.9,
                "credential_harvesting": True,
                "urgency_score": 0.8,
                "risk_score": 0.9
            },
            "sender_analysis": {
                "spoofing_detected": True,
                "risk_score": 0.8
            }
        }
        
        result = await aggregator.analyze_threat_deterministic(
            {"subject": "Test", "content": "Test"}, high_conf_analysis
        )
        
        assert result.confidence_score >= 0.7, f"High-confidence scenario should have high confidence, got {result.confidence_score}"
        assert result.confidence_level in [ConfidenceLevel.HIGH, ConfidenceLevel.VERY_HIGH], \
            f"Should have high confidence level, got {result.confidence_level}"
    
    @pytest.mark.asyncio
    async def test_edge_cases(self, aggregator):
        """Test edge cases and error handling."""
        
        # Empty analysis
        result = await aggregator.analyze_threat_deterministic(
            {"subject": "Test"}, {}
        )
        
        assert 0 <= result.final_score <= 1, "Score should be valid even with empty analysis"
        assert result.threat_category == ThreatCategory.LEGITIMATE, "Empty analysis should be legitimate"
        
        # Malformed analysis
        malformed_analysis = {
            "url_analysis": "invalid",
            "content_analysis": {"invalid": True}
        }
        
        result = await aggregator.analyze_threat_deterministic(
            {"subject": "Test"}, malformed_analysis
        )
        
        assert 0 <= result.final_score <= 1, "Score should be valid even with malformed analysis"
    
    @pytest.mark.asyncio
    async def test_input_hash_uniqueness(self, aggregator):
        """Test that different inputs produce different hashes."""
        
        email1 = {"subject": "Test 1", "content": "Content 1"}
        email2 = {"subject": "Test 2", "content": "Content 2"}
        analysis = {"url_analysis": {"risk_score": 0.5}}
        
        result1 = await aggregator.analyze_threat_deterministic(email1, analysis)
        result2 = await aggregator.analyze_threat_deterministic(email2, analysis)
        
        assert result1.input_hash != result2.input_hash, "Different inputs should have different hashes"
    
    @pytest.mark.asyncio
    async def test_scoring_consistency_bounds(self, aggregator):
        """Test that scores remain within expected bounds."""
        
        # Test various scenarios
        test_cases = [
            # No threats
            ({}, 0.0, 0.2),
            # Low threat
            ({"url_analysis": {"risk_score": 0.3}}, 0.0, 0.4),
            # Medium threat
            ({"url_analysis": {"suspicious_urls": ["http://suspicious.com"]}, 
              "content_analysis": {"urgency_score": 0.6}}, 0.2, 0.7),
            # High threat
            ({"url_analysis": {"malicious_urls": ["http://evil.com"]}, 
              "content_analysis": {"credential_harvesting": True}}, 0.6, 1.0)
        ]
        
        for analysis, min_score, max_score in test_cases:
            result = await aggregator.analyze_threat_deterministic(
                {"subject": "Test"}, analysis
            )
            
            assert min_score <= result.final_score <= max_score, \
                f"Score {result.final_score} should be between {min_score} and {max_score}"
    
    @pytest.mark.asyncio
    async def test_threat_categorization_accuracy(self, aggregator):
        """Test accurate threat categorization."""
        
        # Test category boundaries
        test_cases = [
            # Legitimate
            ({"url_analysis": {"risk_score": 0.1}}, [ThreatCategory.LEGITIMATE]),
            # Suspicious
            ({"content_analysis": {"urgency_score": 0.4}}, [ThreatCategory.LEGITIMATE, ThreatCategory.SUSPICIOUS]),
            # Phishing
            ({"url_analysis": {"malicious_urls": ["http://phish.com"]}, 
              "content_analysis": {"credential_harvesting": True}}, [ThreatCategory.PHISHING, ThreatCategory.SCAM])
        ]
        
        for analysis, expected_categories in test_cases:
            result = await aggregator.analyze_threat_deterministic(
                {"subject": "Test"}, analysis
            )
            
            assert result.threat_category in expected_categories, \
                f"Category {result.threat_category} should be in {expected_categories}"
    
    @pytest.mark.asyncio
    async def test_computation_trace(self, aggregator, sample_phishing_email, sample_phishing_analysis):
        """Test computation trace completeness."""
        
        result = await aggregator.analyze_threat_deterministic(
            sample_phishing_email, sample_phishing_analysis
        )
        
        # Verify trace structure
        assert "algorithm_version" in result.computation_trace
        assert "steps" in result.computation_trace
        assert len(result.computation_trace["steps"]) >= 5, "Should have major computation steps"
        
        # Verify required steps
        step_names = [step["step"] for step in result.computation_trace["steps"]]
        required_steps = ["extract_indicators", "calculate_components", "aggregate_score", 
                         "categorize_threat", "calculate_confidence"]
        
        for required_step in required_steps:
            assert required_step in step_names, f"Should include {required_step} step"
    
    @pytest.mark.asyncio
    async def test_performance_consistency(self, aggregator, sample_phishing_email, sample_phishing_analysis):
        """Test performance and timing consistency."""
        
        # Run multiple analyses and measure timing
        times = []
        for i in range(10):
            start_time = time.time()
            result = await aggregator.analyze_threat_deterministic(
                sample_phishing_email, sample_phishing_analysis
            )
            end_time = time.time()
            times.append(end_time - start_time)
            
            # Verify processing time is recorded
            assert result.processing_time > 0, "Processing time should be recorded"
        
        # Performance should be consistent (not vary wildly)
        avg_time = sum(times) / len(times)
        for time_taken in times:
            assert abs(time_taken - avg_time) < avg_time, "Performance should be relatively consistent"


class TestThreatIndicatorExtraction:
    """Test threat indicator extraction from various analysis components."""
    
    def test_url_indicator_extraction(self):
        """Test extraction of URL-based threat indicators."""
        aggregator = DeterministicThreatAggregator()
        
        url_data = {
            "malicious_urls": ["http://evil.com", "http://phishing.com"],
            "suspicious_urls": ["http://suspicious.com"],
            "typosquatting_detected": True
        }
        
        indicators = aggregator._extract_url_indicators(url_data, time.time())
        
        # Should extract multiple indicators
        assert len(indicators) >= 3, "Should extract malicious URLs, suspicious URLs, and typosquatting"
        
        # Verify indicator types
        indicator_names = [ind.name for ind in indicators]
        assert "malicious_urls" in indicator_names
        assert "suspicious_urls" in indicator_names
        assert "typosquatting" in indicator_names
        
        # Verify values are scaled appropriately
        malicious_indicator = next(ind for ind in indicators if ind.name == "malicious_urls")
        assert malicious_indicator.value > 0.5, "Multiple malicious URLs should have high value"
    
    def test_content_indicator_extraction(self):
        """Test extraction of content-based threat indicators."""
        aggregator = DeterministicThreatAggregator()
        
        content_data = {
            "phishing_indicators": 0.8,
            "phishing_evidence": ["Account verification", "Urgent action required"],
            "urgency_score": 0.9,
            "urgency_keywords": ["URGENT", "immediately"],
            "credential_harvesting": True
        }
        
        indicators = aggregator._extract_content_indicators(content_data, time.time())
        
        # Should extract multiple indicators
        assert len(indicators) >= 3, "Should extract phishing, urgency, and credential harvesting indicators"
        
        # Verify high-value indicators
        phishing_indicator = next(ind for ind in indicators if ind.name == "phishing_keywords")
        assert phishing_indicator.value == 0.8, "Phishing indicator should match input score"
        
        credential_indicator = next(ind for ind in indicators if ind.name == "credential_harvesting")
        assert credential_indicator.value == 0.9, "Credential harvesting should have high value"


async def run_comprehensive_tests():
    """Run comprehensive test suite for deterministic threat aggregator."""
    
    print("🧪 Running Comprehensive Deterministic Threat Aggregator Tests")
    print("=" * 70)
    
    # Initialize test framework
    aggregator = DeterministicThreatAggregator()
    
    # Test 1: Reproducibility
    print("\n🔁 Test 1: Scoring Reproducibility")
    email_data = {"subject": "Test", "content": "Test content"}
    analysis_data = {
        "url_analysis": {"malicious_urls": ["http://evil.com"], "risk_score": 0.8},
        "content_analysis": {"phishing_indicators": 0.7, "risk_score": 0.7}
    }
    
    results = []
    for i in range(5):
        result = await aggregator.analyze_threat_deterministic(email_data, analysis_data)
        results.append(result)
    
    # Verify reproducibility
    scores = [r.final_score for r in results]
    hashes = [r.input_hash for r in results]
    
    print(f"✅ Scores: {scores}")
    print(f"✅ All scores identical: {len(set(scores)) == 1}")
    print(f"✅ All hashes identical: {len(set(hashes)) == 1}")
    
    # Test 2: Threat Detection Accuracy
    print("\n🎯 Test 2: Threat Detection Accuracy")
    
    # High-threat scenario
    high_threat_analysis = {
        "url_analysis": {
            "malicious_urls": ["http://phishing.com", "http://evil.com"],
            "typosquatting_detected": True,
            "risk_score": 0.9
        },
        "content_analysis": {
            "phishing_indicators": 0.85,
            "credential_harvesting": True,
            "urgency_score": 0.8,
            "risk_score": 0.85
        },
        "sender_analysis": {
            "spoofing_detected": True,
            "risk_score": 0.8
        }
    }
    
    high_threat_result = await aggregator.analyze_threat_deterministic(
        {"subject": "URGENT: Verify Account"}, high_threat_analysis
    )
    
    print(f"✅ High-threat score: {high_threat_result.final_score:.3f}")
    print(f"✅ Threat category: {high_threat_result.threat_category.value}")
    print(f"✅ Confidence: {high_threat_result.confidence_score:.3f}")
    
    # Low-threat scenario
    low_threat_analysis = {
        "url_analysis": {"risk_score": 0.1},
        "content_analysis": {"risk_score": 0.05},
        "sender_analysis": {"risk_score": 0.1}
    }
    
    low_threat_result = await aggregator.analyze_threat_deterministic(
        {"subject": "Newsletter"}, low_threat_analysis
    )
    
    print(f"✅ Low-threat score: {low_threat_result.final_score:.3f}")
    print(f"✅ Threat category: {low_threat_result.threat_category.value}")
    
    # Test 3: Explanation Quality
    print("\n📝 Test 3: Explanation Quality")
    print(f"✅ Explanation length: {len(high_threat_result.explanation)} characters")
    print(f"✅ Number of indicators: {len(high_threat_result.indicators)}")
    print(f"✅ Number of components: {len(high_threat_result.components)}")
    print(f"✅ Sample explanation: {high_threat_result.explanation[:200]}...")
    
    # Test 4: Performance
    print("\n⚡ Test 4: Performance Testing")
    
    start_time = time.time()
    for i in range(10):
        await aggregator.analyze_threat_deterministic(email_data, analysis_data)
    end_time = time.time()
    
    avg_time = (end_time - start_time) / 10
    print(f"✅ Average processing time: {avg_time:.4f} seconds")
    print(f"✅ Throughput: {1/avg_time:.1f} analyses/second")
    
    print("\n🎉 All Deterministic Threat Aggregator Tests Completed Successfully!")
    
    return {
        "reproducibility": len(set(scores)) == 1,
        "high_threat_detection": high_threat_result.final_score > 0.7,
        "low_threat_detection": low_threat_result.final_score < 0.3,
        "explanation_quality": len(high_threat_result.explanation) > 100,
        "performance": avg_time < 0.1
    }


if __name__ == "__main__":
    # Run the comprehensive test suite
    test_results = asyncio.run(run_comprehensive_tests())
    
    print("\n📊 Test Results Summary:")
    for test_name, passed in test_results.items():
        status = "✅ PASS" if passed else "❌ FAIL"
        print(f"   {test_name}: {status}")
    
    all_passed = all(test_results.values())
    print(f"\n🎯 Overall Result: {'🎉 ALL TESTS PASSED' if all_passed else '⚠️ SOME TESTS FAILED'}")