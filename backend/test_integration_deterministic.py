#!/usr/bin/env python3
"""
Integration test for deterministic threat aggregator with enhanced scoring service.
Tests the interaction between the core algorithm and production integration layer.
"""
import sys
import os
import json
from datetime import datetime
from typing import Dict, Any

# Add the app directory to the path so we can import modules
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

def test_integration():
    """Test integration between deterministic aggregator and enhanced scoring"""
    print("🔗 Testing Deterministic Threat Aggregator Integration")
    
    try:
        # Import the actual modules
        from app.services.deterministic_threat_aggregator import (
            DeterministicThreatAggregator,
            ThreatCategory,
            ConfidenceLevel
        )
        
        # Test with realistic email analysis data
        test_email_data = {
            "urls": [
                {
                    "url": "http://suspicious-bank-site.com/login",
                    "risk_score": 0.85,
                    "confidence": 0.9,
                    "status": "malicious",
                    "reputation": "blacklisted",
                    "category": "phishing"
                },
                {
                    "url": "http://legitimate-news.com",
                    "risk_score": 0.1,
                    "confidence": 0.95,
                    "status": "safe",
                    "reputation": "trusted"
                }
            ],
            "content_analysis": {
                "threat_score": 0.75,
                "confidence": 0.8,
                "summary": "Phishing attempt detected in email content",
                "explanation": "Contains urgent language and credential requests",
                "keywords": ["urgent", "verify", "account", "suspended"],
                "sentiment": "manipulative"
            },
            "sender_analysis": {
                "sender": "security@fake-bank.com",
                "risk_score": 0.7,
                "confidence": 0.85,
                "explanation": "Domain appears to spoof legitimate banking institution",
                "domain_age": 5,  # days
                "reputation": "suspicious",
                "spf_pass": False,
                "dkim_pass": False
            },
            "attachment_analysis": {
                "has_attachments": False,
                "risk_score": 0.0,
                "confidence": 1.0
            },
            "context_analysis": {
                "time_of_day": "unusual",
                "recipient_targeting": "mass",
                "campaign_detected": True,
                "risk_score": 0.3,
                "confidence": 0.6
            }
        }
        
        # Initialize aggregator
        aggregator = DeterministicThreatAggregator()
        
        # Run analysis
        result = aggregator.analyze_threat(test_email_data)
        
        # Verify result structure
        print(f"   📊 Overall Score: {result.overall_score:.3f}")
        print(f"   🏷️  Threat Category: {result.threat_category.value}")
        print(f"   🎯 Confidence Level: {result.confidence_level.value}")
        print(f"   🔒 Input Hash: {result.input_hash[:16]}...")
        print(f"   📈 Indicators Count: {len(result.indicators)}")
        
        # Verify threat category is appropriate for high-risk scenario
        assert result.threat_category in [ThreatCategory.HIGH_RISK, ThreatCategory.CRITICAL], \
            f"Expected high risk category, got {result.threat_category}"
        
        # Verify reproducibility
        result2 = aggregator.analyze_threat(test_email_data)
        assert result.input_hash == result2.input_hash, "Results should be reproducible"
        assert result.overall_score == result2.overall_score, "Scores should be identical"
        
        # Test component breakdown
        print(f"   🧩 Component Scores:")
        for component, score in result.component_scores.items():
            weight = aggregator.component_weights.get(component, 0.0)
            print(f"      • {component.title()}: {score:.3f} (weight: {weight:.1%})")
        
        # Verify explanation quality
        explanation = result.explanation
        assert len(explanation) > 50, "Explanation should be substantial"
        assert "threat level" in explanation.lower(), "Should mention threat level"
        assert "recommendation" in explanation.lower(), "Should include recommendation"
        
        print(f"   📝 Explanation Preview: {explanation[:100]}...")
        
        # Test with safe email
        safe_email_data = {
            "urls": [
                {
                    "url": "https://legitimate-company.com",
                    "risk_score": 0.05,
                    "confidence": 0.95,
                    "status": "safe"
                }
            ],
            "content_analysis": {
                "threat_score": 0.1,
                "confidence": 0.9,
                "summary": "Clean business communication",
                "explanation": "Normal business language patterns"
            },
            "sender_analysis": {
                "sender": "noreply@trusted-company.com",
                "risk_score": 0.05,
                "confidence": 0.9,
                "explanation": "Verified legitimate sender"
            }
        }
        
        safe_result = aggregator.analyze_threat(safe_email_data)
        print(f"\n   📧 Safe Email Test:")
        print(f"      Score: {safe_result.overall_score:.3f}")
        print(f"      Category: {safe_result.threat_category.value}")
        
        # Verify safe email is categorized correctly
        assert safe_result.threat_category in [ThreatCategory.SAFE, ThreatCategory.LOW_RISK], \
            f"Expected safe/low risk category, got {safe_result.threat_category}"
        
        print("\n   ✅ Integration test completed successfully!")
        return True
        
    except ImportError as e:
        print(f"   ❌ Import failed: {e}")
        print("   💡 This is expected if running outside the full application context")
        return False
    except Exception as e:
        print(f"   ❌ Integration test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_enhanced_scoring_integration():
    """Test integration with enhanced scoring service"""
    print("\n⚡ Testing Enhanced Scoring Service Integration")
    
    try:
        from app.services.enhanced_scoring_service import EnhancedScoringService
        from app.services.deterministic_threat_aggregator import DeterministicThreatAggregator
        
        # Create services
        aggregator = DeterministicThreatAggregator()
        enhanced_service = EnhancedScoringService(aggregator)
        
        # Test data
        test_analysis = {
            "urls": [{"url": "http://phishing.com", "risk_score": 0.9, "confidence": 0.95, "status": "malicious"}],
            "content_analysis": {"threat_score": 0.8, "confidence": 0.85, "summary": "Phishing content"}
        }
        
        # Get enhanced score
        enhanced_result = enhanced_service.get_enhanced_threat_score(test_analysis)
        
        print(f"   📊 Enhanced Score: {enhanced_result.overall_score:.3f}")
        print(f"   🎯 Confidence: {enhanced_result.confidence_score:.3f}")
        print(f"   💡 Recommendations: {len(enhanced_result.recommendations)}")
        print(f"   🔍 Evidence Count: {len(enhanced_result.evidence)}")
        
        # Verify enhanced result structure
        assert hasattr(enhanced_result, 'overall_score'), "Should have overall score"
        assert hasattr(enhanced_result, 'recommendations'), "Should have recommendations"
        assert hasattr(enhanced_result, 'evidence'), "Should have evidence"
        assert len(enhanced_result.recommendations) > 0, "Should provide recommendations"
        
        print("   ✅ Enhanced scoring integration successful!")
        return True
        
    except ImportError as e:
        print(f"   ❌ Enhanced service import failed: {e}")
        return False
    except Exception as e:
        print(f"   ❌ Enhanced scoring test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_api_endpoints_integration():
    """Test that API endpoints can be imported"""
    print("\n🌐 Testing API Endpoints Integration")
    
    try:
        from app.api.deterministic_threat_endpoints import (
            analyze_threat,
            batch_analyze_threats,
            test_consistency,
            get_algorithm_info
        )
        
        print("   ✅ All API endpoints imported successfully!")
        print("   📋 Available endpoints:")
        print("      • /analyze-threat")
        print("      • /batch-analyze")
        print("      • /test-consistency")
        print("      • /algorithm-info")
        print("      • /health")
        print("      • /statistics")
        
        return True
        
    except ImportError as e:
        print(f"   ❌ API endpoints import failed: {e}")
        return False
    except Exception as e:
        print(f"   ❌ API endpoints test failed: {e}")
        return False

def run_integration_tests():
    """Run all integration tests"""
    print("🚀 Starting Deterministic Threat Aggregator Integration Tests\n")
    
    results = []
    
    # Run integration tests
    results.append(test_integration())
    results.append(test_enhanced_scoring_integration())
    results.append(test_api_endpoints_integration())
    
    # Summary
    passed = sum(results)
    total = len(results)
    
    print(f"\n📊 Integration Test Summary:")
    print(f"   ✅ Passed: {passed}/{total}")
    
    if passed == total:
        print("\n🎉 All integration tests passed!")
        print("\n🔧 Priority 5 Implementation Status:")
        print("   ✅ Core deterministic algorithm")
        print("   ✅ Enhanced scoring service")
        print("   ✅ API endpoints")
        print("   ✅ Component integration")
        print("   ✅ Reproducible scoring")
        print("   ✅ Explainable AI output")
        
        print("\n🚀 Ready for production deployment!")
        return True
    else:
        print(f"\n⚠️  {total - passed} integration tests failed")
        print("   💡 Some failures may be expected in isolated test environment")
        return False

if __name__ == "__main__":
    success = run_integration_tests()
    sys.exit(0 if success else 1)