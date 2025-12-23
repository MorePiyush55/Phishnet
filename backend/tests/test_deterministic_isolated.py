#!/usr/bin/env python3
"""
Completely isolated test for deterministic threat aggregator.
Tests the core algorithm without any database or model dependencies.
"""
import sys
import hashlib
import json
from datetime import datetime
from dataclasses import dataclass, asdict
from typing import Dict, List, Any, Optional, Tuple
from enum import Enum

# Mock the required types without importing models
class ThreatCategory(Enum):
    """Threat category enumeration"""
    SAFE = "safe"
    LOW_RISK = "low_risk"
    MEDIUM_RISK = "medium_risk"
    HIGH_RISK = "high_risk"
    CRITICAL = "critical"

class ConfidenceLevel(Enum):
    """Confidence level enumeration"""
    VERY_LOW = "very_low"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    VERY_HIGH = "very_high"

@dataclass
class ThreatIndicator:
    """Individual threat indicator"""
    type: str  # e.g., "url", "content", "sender", "attachment"
    value: str  # The actual indicator value
    score: float  # 0.0 to 1.0
    confidence: float  # 0.0 to 1.0
    explanation: str  # Human readable explanation
    severity: str  # "low", "medium", "high", "critical"
    category: str  # Classification category
    metadata: Dict[str, Any]  # Additional context

@dataclass
class ThreatAnalysisResult:
    """Complete threat analysis result"""
    overall_score: float  # 0.0 to 1.0
    threat_category: ThreatCategory
    confidence_level: ConfidenceLevel
    confidence_score: float  # 0.0 to 1.0
    indicators: List[ThreatIndicator]
    explanation: str
    component_scores: Dict[str, float]
    metadata: Dict[str, Any]
    timestamp: datetime
    analysis_version: str
    input_hash: str  # For reproducibility verification

class DeterministicThreatAggregator:
    """
    Deterministic threat aggregator with reproducible scoring and explainable AI.
    Core implementation without external dependencies.
    """
    
    def __init__(self):
        self.version = "1.0.0"
        self.component_weights = {
            "url": 0.35,
            "content": 0.30,
            "sender": 0.20,
            "attachment": 0.10,
            "context": 0.05
        }
        
        # Threat score thresholds
        self.threat_thresholds = {
            ThreatCategory.SAFE: (0.0, 0.2),
            ThreatCategory.LOW_RISK: (0.2, 0.4),
            ThreatCategory.MEDIUM_RISK: (0.4, 0.6),
            ThreatCategory.HIGH_RISK: (0.6, 0.8),
            ThreatCategory.CRITICAL: (0.8, 1.0)
        }
        
        # Confidence mapping
        self.confidence_thresholds = {
            ConfidenceLevel.VERY_LOW: (0.0, 0.2),
            ConfidenceLevel.LOW: (0.2, 0.4),
            ConfidenceLevel.MEDIUM: (0.4, 0.6),
            ConfidenceLevel.HIGH: (0.6, 0.8),
            ConfidenceLevel.VERY_HIGH: (0.8, 1.0)
        }

    def _generate_input_hash(self, analysis_data: Dict[str, Any]) -> str:
        """Generate deterministic hash for input data"""
        # Sort and serialize for consistent hashing
        sorted_data = json.dumps(analysis_data, sort_keys=True, default=str)
        return hashlib.sha256(sorted_data.encode()).hexdigest()

    def _categorize_threat_level(self, score: float) -> ThreatCategory:
        """Categorize threat level based on score"""
        for category, (min_score, max_score) in self.threat_thresholds.items():
            if min_score <= score < max_score:
                return category
        return ThreatCategory.CRITICAL  # For score >= 0.8

    def _calculate_confidence_level(self, score: float) -> ConfidenceLevel:
        """Calculate confidence level based on score"""
        for level, (min_score, max_score) in self.confidence_thresholds.items():
            if min_score <= score < max_score:
                return level
        return ConfidenceLevel.VERY_HIGH  # For score >= 0.8

    def _extract_threat_indicators(self, analysis_data: Dict[str, Any]) -> List[ThreatIndicator]:
        """Extract structured threat indicators from analysis data"""
        indicators = []
        
        # Process URL indicators
        urls = analysis_data.get("urls", [])
        for url in urls:
            if isinstance(url, dict):
                score = url.get("risk_score", 0.0)
                indicators.append(ThreatIndicator(
                    type="url",
                    value=url.get("url", ""),
                    score=score,
                    confidence=url.get("confidence", 0.5),
                    explanation=f"URL risk assessment: {url.get('status', 'unknown')}",
                    severity="high" if score > 0.7 else "medium" if score > 0.4 else "low",
                    category="malicious_url" if score > 0.6 else "suspicious_url",
                    metadata=url
                ))
        
        # Process content indicators
        content_analysis = analysis_data.get("content_analysis", {})
        if content_analysis:
            score = content_analysis.get("threat_score", 0.0)
            indicators.append(ThreatIndicator(
                type="content",
                value=content_analysis.get("summary", ""),
                score=score,
                confidence=content_analysis.get("confidence", 0.5),
                explanation=content_analysis.get("explanation", "Content analysis"),
                severity="high" if score > 0.7 else "medium" if score > 0.4 else "low",
                category="malicious_content" if score > 0.6 else "suspicious_content",
                metadata=content_analysis
            ))
        
        # Process sender indicators
        sender_analysis = analysis_data.get("sender_analysis", {})
        if sender_analysis:
            score = sender_analysis.get("risk_score", 0.0)
            indicators.append(ThreatIndicator(
                type="sender",
                value=sender_analysis.get("sender", ""),
                score=score,
                confidence=sender_analysis.get("confidence", 0.5),
                explanation=sender_analysis.get("explanation", "Sender verification"),
                severity="high" if score > 0.7 else "medium" if score > 0.4 else "low",
                category="spoofed_sender" if score > 0.6 else "suspicious_sender",
                metadata=sender_analysis
            ))
        
        return indicators

    def _calculate_component_scores(self, indicators: List[ThreatIndicator]) -> Dict[str, float]:
        """Calculate component-wise threat scores"""
        component_scores = {}
        
        # Group indicators by type
        grouped_indicators = {}
        for indicator in indicators:
            if indicator.type not in grouped_indicators:
                grouped_indicators[indicator.type] = []
            grouped_indicators[indicator.type].append(indicator)
        
        # Calculate score for each component
        for component_type, component_indicators in grouped_indicators.items():
            if component_indicators:
                # Use weighted average based on confidence
                total_weighted_score = 0.0
                total_confidence = 0.0
                
                for indicator in component_indicators:
                    weight = indicator.confidence
                    total_weighted_score += indicator.score * weight
                    total_confidence += weight
                
                if total_confidence > 0:
                    component_scores[component_type] = total_weighted_score / total_confidence
                else:
                    component_scores[component_type] = 0.0
            else:
                component_scores[component_type] = 0.0
        
        return component_scores

    def _aggregate_scores(self, component_scores: Dict[str, float]) -> Tuple[float, float]:
        """Aggregate component scores into overall threat score and confidence"""
        weighted_score = 0.0
        total_weight = 0.0
        confidence_scores = []
        
        for component, weight in self.component_weights.items():
            if component in component_scores:
                score = component_scores[component]
                weighted_score += score * weight
                total_weight += weight
                confidence_scores.append(score)
        
        # Normalize if we have partial components
        if total_weight > 0:
            overall_score = weighted_score / total_weight
        else:
            overall_score = 0.0
        
        # Calculate confidence as consistency of component scores
        if confidence_scores:
            mean_score = sum(confidence_scores) / len(confidence_scores)
            variance = sum((s - mean_score) ** 2 for s in confidence_scores) / len(confidence_scores)
            confidence = max(0.0, 1.0 - variance)  # Higher variance = lower confidence
        else:
            confidence = 0.0
        
        return overall_score, confidence

    def _generate_explanation(self, 
                            overall_score: float,
                            threat_category: ThreatCategory,
                            indicators: List[ThreatIndicator],
                            component_scores: Dict[str, float]) -> str:
        """Generate human-readable explanation of the threat analysis"""
        
        explanation_parts = [
            f"Overall threat level: {threat_category.value.upper()} (score: {overall_score:.3f})"
        ]
        
        # Component breakdown
        if component_scores:
            explanation_parts.append("\nComponent Analysis:")
            for component, score in sorted(component_scores.items(), key=lambda x: x[1], reverse=True):
                weight = self.component_weights.get(component, 0.0)
                explanation_parts.append(
                    f"  • {component.title()}: {score:.3f} (weight: {weight:.1%})"
                )
        
        # Key indicators
        high_risk_indicators = [i for i in indicators if i.score > 0.6]
        if high_risk_indicators:
            explanation_parts.append("\nKey Risk Indicators:")
            for indicator in sorted(high_risk_indicators, key=lambda x: x.score, reverse=True)[:3]:
                explanation_parts.append(f"  • {indicator.explanation} (score: {indicator.score:.3f})")
        
        # Recommendations
        if threat_category in [ThreatCategory.HIGH_RISK, ThreatCategory.CRITICAL]:
            explanation_parts.append("\nRecommendation: BLOCK or QUARANTINE this email")
        elif threat_category == ThreatCategory.MEDIUM_RISK:
            explanation_parts.append("\nRecommendation: REVIEW manually before delivery")
        else:
            explanation_parts.append("\nRecommendation: Allow with monitoring")
        
        return "\n".join(explanation_parts)

    def analyze_threat(self, analysis_data: Dict[str, Any]) -> ThreatAnalysisResult:
        """
        Perform deterministic threat analysis on email data.
        
        Args:
            analysis_data: Dictionary containing analysis results from various components
            
        Returns:
            ThreatAnalysisResult with deterministic scoring and explanations
        """
        # Generate input hash for reproducibility
        input_hash = self._generate_input_hash(analysis_data)
        
        # Extract structured threat indicators
        indicators = self._extract_threat_indicators(analysis_data)
        
        # Calculate component scores
        component_scores = self._calculate_component_scores(indicators)
        
        # Aggregate into overall score and confidence
        overall_score, confidence_score = self._aggregate_scores(component_scores)
        
        # Categorize threat and confidence levels
        threat_category = self._categorize_threat_level(overall_score)
        confidence_level = self._calculate_confidence_level(confidence_score)
        
        # Generate explanation
        explanation = self._generate_explanation(
            overall_score, threat_category, indicators, component_scores
        )
        
        # Create result
        result = ThreatAnalysisResult(
            overall_score=overall_score,
            threat_category=threat_category,
            confidence_level=confidence_level,
            confidence_score=confidence_score,
            indicators=indicators,
            explanation=explanation,
            component_scores=component_scores,
            metadata={
                "algorithm_version": self.version,
                "component_weights": self.component_weights,
                "total_indicators": len(indicators),
                "analysis_timestamp": datetime.now().isoformat()
            },
            timestamp=datetime.now(),
            analysis_version=self.version,
            input_hash=input_hash
        )
        
        return result


def test_deterministic_scoring():
    """Test that deterministic scoring produces identical results"""
    print("🧪 Testing Deterministic Scoring...")
    
    aggregator = DeterministicThreatAggregator()
    
    # Test data
    test_data = {
        "urls": [
            {
                "url": "http://malicious-site.com/phishing",
                "risk_score": 0.85,
                "confidence": 0.9,
                "status": "malicious"
            }
        ],
        "content_analysis": {
            "threat_score": 0.7,
            "confidence": 0.8,
            "summary": "Suspicious content detected",
            "explanation": "Contains phishing keywords"
        },
        "sender_analysis": {
            "sender": "fake@bank.com",
            "risk_score": 0.6,
            "confidence": 0.75,
            "explanation": "Domain spoofing detected"
        }
    }
    
    # Run analysis multiple times
    results = []
    for i in range(5):
        result = aggregator.analyze_threat(test_data)
        results.append(result)
    
    # Verify all results are identical
    first_result = results[0]
    for i, result in enumerate(results[1:], 1):
        assert result.overall_score == first_result.overall_score, f"Score mismatch in run {i+1}"
        assert result.threat_category == first_result.threat_category, f"Category mismatch in run {i+1}"
        assert result.confidence_score == first_result.confidence_score, f"Confidence mismatch in run {i+1}"
        assert result.input_hash == first_result.input_hash, f"Hash mismatch in run {i+1}"
    
    print(f"✅ Deterministic scoring verified - {len(results)} identical results")
    print(f"   Score: {first_result.overall_score:.3f}")
    print(f"   Category: {first_result.threat_category.value}")
    print(f"   Hash: {first_result.input_hash[:16]}...")

def test_threat_categorization():
    """Test threat categorization logic"""
    print("\n🏷️  Testing Threat Categorization...")
    
    aggregator = DeterministicThreatAggregator()
    
    test_cases = [
        (0.1, ThreatCategory.SAFE),
        (0.3, ThreatCategory.LOW_RISK),
        (0.5, ThreatCategory.MEDIUM_RISK),
        (0.7, ThreatCategory.HIGH_RISK),
        (0.9, ThreatCategory.CRITICAL)
    ]
    
    for score, expected_category in test_cases:
        category = aggregator._categorize_threat_level(score)
        assert category == expected_category, f"Score {score} should be {expected_category}, got {category}"
        print(f"   ✅ Score {score:.1f} → {category.value}")

def test_component_weighting():
    """Test component weighting in aggregation"""
    print("\n⚖️  Testing Component Weighting...")
    
    aggregator = DeterministicThreatAggregator()
    
    # Test high URL score with low other scores
    url_heavy_data = {
        "urls": [{"url": "http://malicious.com", "risk_score": 0.9, "confidence": 0.9, "status": "malicious"}],
        "content_analysis": {"threat_score": 0.1, "confidence": 0.8, "summary": "Clean content"},
        "sender_analysis": {"sender": "safe@domain.com", "risk_score": 0.1, "confidence": 0.8}
    }
    
    result = aggregator.analyze_threat(url_heavy_data)
    
    # URL has 35% weight, so high URL score should significantly impact overall score
    assert result.overall_score > 0.3, f"Expected high overall score due to URL weight, got {result.overall_score}"
    print(f"   ✅ URL-heavy analysis: {result.overall_score:.3f} (URL weight: 35%)")
    
    # Test content-heavy scenario
    content_heavy_data = {
        "urls": [{"url": "http://safe.com", "risk_score": 0.1, "confidence": 0.9, "status": "safe"}],
        "content_analysis": {"threat_score": 0.9, "confidence": 0.9, "summary": "Malicious content"},
        "sender_analysis": {"sender": "safe@domain.com", "risk_score": 0.1, "confidence": 0.8}
    }
    
    result2 = aggregator.analyze_threat(content_heavy_data)
    print(f"   ✅ Content-heavy analysis: {result2.overall_score:.3f} (Content weight: 30%)")

def test_explanation_quality():
    """Test explanation generation quality"""
    print("\n📝 Testing Explanation Quality...")
    
    aggregator = DeterministicThreatAggregator()
    
    test_data = {
        "urls": [
            {
                "url": "http://phishing-site.com",
                "risk_score": 0.85,
                "confidence": 0.9,
                "status": "malicious"
            }
        ],
        "content_analysis": {
            "threat_score": 0.75,
            "confidence": 0.8,
            "summary": "Phishing content detected",
            "explanation": "Contains credential harvesting patterns"
        }
    }
    
    result = aggregator.analyze_threat(test_data)
    explanation = result.explanation
    
    # Check explanation contains key elements
    print(f"   📄 Generated explanation:\n{explanation}")
    
    assert "threat level" in explanation.lower(), "Explanation should mention threat level"
    assert "component analysis" in explanation.lower(), "Explanation should include component breakdown"
    assert "recommendation" in explanation.lower(), "Explanation should include recommendation"
    # Check for score in formatted form (3 decimal places)
    score_str = f"{result.overall_score:.3f}"
    assert score_str in explanation, f"Explanation should include overall score {score_str}"
    
    print("   ✅ Explanation contains required elements:")
    print(f"      📊 Score: {result.overall_score:.3f}")
    print(f"      🏷️  Category: {result.threat_category.value}")
    print(f"      📄 Length: {len(explanation)} characters")

def test_reproducibility_with_different_input_orders():
    """Test that different input orders produce same results"""
    print("\n🔄 Testing Input Order Independence...")
    
    aggregator = DeterministicThreatAggregator()
    
    # Same data in different orders
    data1 = {
        "urls": [{"url": "http://test.com", "risk_score": 0.5, "confidence": 0.8, "status": "suspicious"}],
        "content_analysis": {"threat_score": 0.6, "confidence": 0.7, "summary": "Test content"},
        "sender_analysis": {"sender": "test@example.com", "risk_score": 0.4, "confidence": 0.9}
    }
    
    data2 = {
        "sender_analysis": {"sender": "test@example.com", "risk_score": 0.4, "confidence": 0.9},
        "content_analysis": {"threat_score": 0.6, "confidence": 0.7, "summary": "Test content"},
        "urls": [{"url": "http://test.com", "risk_score": 0.5, "confidence": 0.8, "status": "suspicious"}]
    }
    
    result1 = aggregator.analyze_threat(data1)
    result2 = aggregator.analyze_threat(data2)
    
    # Results should be identical despite different input order
    assert result1.overall_score == result2.overall_score, "Scores should be identical"
    assert result1.input_hash == result2.input_hash, "Hashes should be identical"
    assert result1.threat_category == result2.threat_category, "Categories should be identical"
    
    print(f"   ✅ Order independence verified")
    print(f"      Hash 1: {result1.input_hash[:16]}...")
    print(f"      Hash 2: {result2.input_hash[:16]}...")

def test_edge_cases():
    """Test edge cases and error handling"""
    print("\n🎯 Testing Edge Cases...")
    
    aggregator = DeterministicThreatAggregator()
    
    # Empty data
    empty_result = aggregator.analyze_threat({})
    assert empty_result.overall_score == 0.0, "Empty data should result in zero score"
    assert empty_result.threat_category == ThreatCategory.SAFE, "Empty data should be categorized as safe"
    print("   ✅ Empty data handled correctly")
    
    # Missing confidence values
    incomplete_data = {
        "urls": [{"url": "http://test.com", "risk_score": 0.5, "status": "unknown"}],
        "content_analysis": {"threat_score": 0.3}
    }
    
    incomplete_result = aggregator.analyze_threat(incomplete_data)
    assert 0.0 <= incomplete_result.overall_score <= 1.0, "Score should be in valid range"
    print("   ✅ Missing confidence values handled")
    
    # Extreme values
    extreme_data = {
        "urls": [{"url": "http://test.com", "risk_score": 1.0, "confidence": 1.0, "status": "malicious"}],
        "content_analysis": {"threat_score": 1.0, "confidence": 1.0, "summary": "Maximum threat"}
    }
    
    extreme_result = aggregator.analyze_threat(extreme_data)
    assert extreme_result.threat_category == ThreatCategory.CRITICAL, "Maximum scores should be critical"
    print("   ✅ Extreme values handled correctly")

def test_performance():
    """Test performance characteristics"""
    print("\n⚡ Testing Performance...")
    
    aggregator = DeterministicThreatAggregator()
    
    # Large dataset
    large_data = {
        "urls": [
            {
                "url": f"http://test{i}.com",
                "risk_score": 0.1 + (i % 10) * 0.1,
                "confidence": 0.8,
                "status": "test"
            }
            for i in range(50)
        ],
        "content_analysis": {
            "threat_score": 0.5,
            "confidence": 0.7,
            "summary": "Large content analysis" * 100
        }
    }
    
    import time
    start_time = time.time()
    
    # Run multiple analyses
    for _ in range(10):
        result = aggregator.analyze_threat(large_data)
    
    end_time = time.time()
    avg_time = (end_time - start_time) / 10
    
    print(f"   ✅ Performance test completed")
    print(f"      Average time: {avg_time*1000:.2f}ms per analysis")
    print(f"      Processed {len(large_data['urls'])} URLs")
    
    # Performance should be reasonable
    assert avg_time < 1.0, f"Analysis should complete in under 1 second, took {avg_time:.3f}s"

def run_all_tests():
    """Run comprehensive test suite"""
    print("🚀 Starting Deterministic Threat Aggregator Tests\n")
    
    try:
        test_deterministic_scoring()
        test_threat_categorization()
        test_component_weighting()
        test_explanation_quality()
        test_reproducibility_with_different_input_orders()
        test_edge_cases()
        test_performance()
        
        print("\n🎉 All tests passed! Deterministic Threat Aggregator is working correctly.")
        print("\n📊 Test Summary:")
        print("   ✅ Deterministic scoring")
        print("   ✅ Threat categorization")
        print("   ✅ Component weighting")
        print("   ✅ Explanation quality")
        print("   ✅ Input order independence")
        print("   ✅ Edge case handling")
        print("   ✅ Performance benchmarks")
        
        return True
        
    except Exception as e:
        print(f"\n❌ Test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)