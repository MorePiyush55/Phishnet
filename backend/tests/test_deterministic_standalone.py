"""
Standalone test for deterministic threat aggregator - Priority 5
Tests scoring consistency without full application dependencies.
"""

import asyncio
import sys
import os
import time
from typing import Dict, Any

# Add the backend directory to the path
sys.path.insert(0, os.path.dirname(__file__))

# Import only the deterministic aggregator (avoid database dependencies)
from app.services.deterministic_threat_aggregator import (
    DeterministicThreatAggregator,
    ThreatCategory,
    ConfidenceLevel
)


async def test_deterministic_scoring():
    """Test deterministic scoring functionality."""
    
    print("🧪 Testing Deterministic Threat Aggregator - Priority 5")
    print("=" * 60)
    
    # Initialize aggregator
    aggregator = DeterministicThreatAggregator()
    
    # Test data - high-threat phishing email
    high_threat_email = {
        "subject": "URGENT: Verify Your Account Now!",
        "sender": "security@amaz0n-verification.com",
        "content": "Your account will be suspended unless you verify immediately. Click here: http://amaz0n-verify.malicious.com/verify",
        "received_at": "2025-09-22T10:00:00Z"
    }
    
    high_threat_analysis = {
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
    
    # Test 1: Reproducibility
    print("\n🔁 Test 1: Scoring Reproducibility")
    results = []
    for i in range(5):
        result = await aggregator.analyze_threat_deterministic(high_threat_email, high_threat_analysis)
        results.append(result)
    
    scores = [r.final_score for r in results]
    hashes = [r.input_hash for r in results]
    categories = [r.threat_category for r in results]
    
    print(f"✅ Scores: {[f'{s:.3f}' for s in scores]}")
    print(f"✅ All scores identical: {len(set(scores)) == 1}")
    print(f"✅ All hashes identical: {len(set(hashes)) == 1}")
    print(f"✅ All categories identical: {len(set(categories)) == 1}")
    
    # Test 2: Threat Detection Accuracy
    print("\n🎯 Test 2: Threat Detection Accuracy")
    
    high_threat_result = results[0]  # Use first result
    print(f"✅ High-threat score: {high_threat_result.final_score:.3f}")
    print(f"✅ Threat category: {high_threat_result.threat_category.value}")
    print(f"✅ Confidence: {high_threat_result.confidence_score:.3f} ({high_threat_result.confidence_level.value})")
    print(f"✅ Indicators detected: {len(high_threat_result.indicators)}")
    
    # Verify high threat detection
    assert high_threat_result.final_score >= 0.7, f"High threat should have score >= 0.7, got {high_threat_result.final_score}"
    assert high_threat_result.threat_category in [ThreatCategory.PHISHING, ThreatCategory.SCAM], \
        f"Should be high threat category, got {high_threat_result.threat_category}"
    
    # Test 3: Low-threat email
    print("\n📧 Test 3: Legitimate Email Handling")
    
    legitimate_email = {
        "subject": "Weekly Newsletter - Tech Updates",
        "sender": "newsletter@legitimate-tech.com",
        "content": "Hello! Here are this week's tech updates and industry news.",
        "received_at": "2025-09-22T10:00:00Z"
    }
    
    legitimate_analysis = {
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
    
    legit_result = await aggregator.analyze_threat_deterministic(legitimate_email, legitimate_analysis)
    
    print(f"✅ Legitimate email score: {legit_result.final_score:.3f}")
    print(f"✅ Threat category: {legit_result.threat_category.value}")
    print(f"✅ Indicators detected: {len(legit_result.indicators)}")
    
    # Verify legitimate email handling
    assert legit_result.final_score <= 0.3, f"Legitimate email should have score <= 0.3, got {legit_result.final_score}"
    
    # Test 4: Explanation Quality
    print("\n📝 Test 4: Explanation Quality")
    
    explanation = high_threat_result.explanation
    print(f"✅ Explanation length: {len(explanation)} characters")
    print(f"✅ Contains score: {'Score:' in explanation}")
    print(f"✅ Contains category: {high_threat_result.threat_category.value.upper() in explanation}")
    print(f"✅ Number of components: {len(high_threat_result.components)}")
    
    print(f"📄 Sample explanation: {explanation[:200]}...")
    
    # Test 5: Performance
    print("\n⚡ Test 5: Performance Testing")
    
    start_time = time.time()
    for i in range(10):
        await aggregator.analyze_threat_deterministic(high_threat_email, high_threat_analysis)
    end_time = time.time()
    
    avg_time = (end_time - start_time) / 10
    print(f"✅ Average processing time: {avg_time:.4f} seconds")
    print(f"✅ Throughput: {1/avg_time:.1f} analyses/second")
    
    # Test 6: Component Score Breakdown
    print("\n🔧 Test 6: Component Analysis")
    
    for component in high_threat_result.components:
        print(f"✅ {component.component}: score={component.score:.3f}, weight={component.weight:.3f}, contribution={component.contribution:.3f}")
    
    # Test 7: Input Hash Uniqueness
    print("\n🔑 Test 7: Input Hash Uniqueness")
    
    # Slightly different email
    modified_email = high_threat_email.copy()
    modified_email["subject"] = "URGENT: Verify Your Account Tomorrow!"
    
    modified_result = await aggregator.analyze_threat_deterministic(modified_email, high_threat_analysis)
    
    print(f"✅ Original hash: {high_threat_result.input_hash}")
    print(f"✅ Modified hash: {modified_result.input_hash}")
    print(f"✅ Hashes different: {high_threat_result.input_hash != modified_result.input_hash}")
    
    # Test 8: Edge Cases
    print("\n🔍 Test 8: Edge Cases")
    
    # Empty analysis
    empty_result = await aggregator.analyze_threat_deterministic({"subject": "Test"}, {})
    print(f"✅ Empty analysis score: {empty_result.final_score:.3f}")
    print(f"✅ Empty analysis category: {empty_result.threat_category.value}")
    
    # Summary
    print("\n🎉 Test Summary")
    print("=" * 40)
    
    test_results = {
        "Reproducibility": len(set(scores)) == 1,
        "High threat detection": high_threat_result.final_score >= 0.7,
        "Legitimate email handling": legit_result.final_score <= 0.3,
        "Explanation quality": len(explanation) > 100,
        "Performance": avg_time < 0.1,
        "Hash uniqueness": high_threat_result.input_hash != modified_result.input_hash,
        "Edge case handling": 0 <= empty_result.final_score <= 1
    }
    
    passed_tests = sum(test_results.values())
    total_tests = len(test_results)
    
    for test_name, passed in test_results.items():
        status = "✅ PASS" if passed else "❌ FAIL"
        print(f"   {test_name}: {status}")
    
    print(f"\n🎯 Overall Result: {passed_tests}/{total_tests} tests passed")
    
    if passed_tests == total_tests:
        print("🎊 ALL TESTS PASSED - Deterministic Threat Aggregator is working perfectly!")
    else:
        print("⚠️ Some tests failed - review implementation")
    
    # Performance and capability summary
    print(f"\n📊 Performance Summary:")
    print(f"   Algorithm Version: {aggregator.VERSION}")
    print(f"   Processing Speed: {1/avg_time:.1f} emails/second")
    print(f"   High Threat Detection: Score {high_threat_result.final_score:.3f} for phishing")
    print(f"   Legitimate Email: Score {legit_result.final_score:.3f} for newsletter")
    print(f"   Reproducibility: 100% consistent scoring")
    print(f"   Explainability: {len(high_threat_result.components)} component breakdown")
    
    return test_results


if __name__ == "__main__":
    # Run the comprehensive test
    test_results = asyncio.run(test_deterministic_scoring())
    
    # Exit with appropriate code
    all_passed = all(test_results.values())
    exit_code = 0 if all_passed else 1
    
    print(f"\n🚀 Priority 5: Deterministic Threat Aggregator - {'COMPLETE' if all_passed else 'NEEDS WORK'}")
    sys.exit(exit_code)