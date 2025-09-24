"""
Demonstration of Enhanced ThreatAggregator with Deterministic Scoring and Explainability

This script showcases the new features:
1. Deterministic scoring - same inputs always produce identical outputs
2. Configurable threshold profiles (strict/balanced/lenient)
3. Structured explanations with component breakdown
4. Confidence intervals and uncertainty quantification
5. Top contributing signals with evidence
"""

import json
from datetime import datetime, timezone
from typing import List

from app.services.threat_aggregator import (
    ThreatAggregator,
    ThreatAggregatorConfig,
    ComponentScore,
    ComponentType,
    ThresholdProfile,
    strict_aggregator,
    balanced_aggregator,
    lenient_aggregator
)


def create_sample_email_analysis() -> List[ComponentScore]:
    """Create sample component scores simulating a phishing email analysis."""
    
    timestamp = datetime.now(timezone.utc)
    
    # Gemini LLM analysis - detected sophisticated phishing
    gemini_score = ComponentScore(
        component_type=ComponentType.GEMINI_LLM,
        score=0.85,
        confidence=0.92,
        signals=[
            "credential_harvesting_detected",
            "brand_impersonation",
            "urgency_language",
            "suspicious_links",
            "social_engineering_tactics"
        ],
        metadata={
            "model_version": "gemini-1.5-pro",
            "analysis_confidence": 0.92,
            "detected_brand": "microsoft",
            "urgency_score": 0.78,
            "link_analysis": {
                "suspicious_domains": ["secure-microsoft-login.com"],
                "redirect_chains": 2
            }
        },
        processing_time=1.8,
        timestamp=timestamp,
        version="1.0"
    )
    
    # VirusTotal analysis - domain flagged by multiple engines
    virustotal_score = ComponentScore(
        component_type=ComponentType.VIRUS_TOTAL,
        score=0.72,
        confidence=0.88,
        signals=[
            "malicious_domain",
            "phishing_category",
            "recently_registered",
            "suspicious_tld"
        ],
        metadata={
            "positive_detections": 12,
            "total_engines": 70,
            "detection_ratio": "12/70",
            "categories": ["phishing", "malware"],
            "first_seen": "2024-01-10",
            "domain_age_days": 5
        },
        processing_time=0.6,
        timestamp=timestamp,
        version="1.0"
    )
    
    # AbuseIPDB analysis - IP has abuse history
    abuseipdb_score = ComponentScore(
        component_type=ComponentType.ABUSEIPDB,
        score=0.65,
        confidence=0.75,
        signals=[
            "abuse_reports",
            "datacenter_hosting",
            "suspicious_geolocation"
        ],
        metadata={
            "abuse_confidence": 65,
            "total_reports": 28,
            "country_code": "RU",
            "usage_type": "datacenter",
            "isp": "Unknown Hosting Provider",
            "last_reported": "2024-01-14"
        },
        processing_time=0.4,
        timestamp=timestamp,
        version="1.0"
    )
    
    # Link Redirect Analyzer - suspicious redirect chain
    redirect_score = ComponentScore(
        component_type=ComponentType.LINK_REDIRECT,
        score=0.78,
        confidence=0.82,
        signals=[
            "redirect_chain",
            "url_shortener",
            "cloaking_detected",
            "mismatched_domain"
        ],
        metadata={
            "redirect_chain": [
                "bit.ly/secure-login",
                "redirector.service.com",
                "secure-microsoft-login.com"
            ],
            "chain_length": 3,
            "final_domain": "secure-microsoft-login.com",
            "cloaking_score": 0.68,
            "shortener_services": ["bit.ly"]
        },
        processing_time=2.3,
        timestamp=timestamp,
        version="1.0"
    )
    
    # ML Content Analysis - pattern matching
    ml_score = ComponentScore(
        component_type=ComponentType.ML_CONTENT,
        score=0.71,
        confidence=0.86,
        signals=[
            "phishing_patterns",
            "credential_request",
            "brand_keywords",
            "suspicious_formatting"
        ],
        metadata={
            "model_version": "phishing_classifier_v2.1",
            "prediction_confidence": 0.86,
            "feature_scores": {
                "text_similarity": 0.73,
                "url_features": 0.68,
                "formatting_analysis": 0.75
            },
            "matched_patterns": [
                "verify_account_pattern",
                "urgent_action_pattern",
                "microsoft_impersonation"
            ]
        },
        processing_time=0.9,
        timestamp=timestamp,
        version="1.0"
    )
    
    return [gemini_score, virustotal_score, abuseipdb_score, redirect_score, ml_score]


def demonstrate_deterministic_scoring():
    """Demonstrate that aggregation produces identical results."""
    
    print("=== DETERMINISTIC SCORING DEMONSTRATION ===\n")
    
    aggregator = balanced_aggregator
    components = create_sample_email_analysis()
    target = "email_suspicious_microsoft_login_2024_01_15"
    
    print("Running aggregation 5 times with identical inputs...\n")
    
    results = []
    for i in range(5):
        result = aggregator.aggregate_threat_scores(components, target)
        results.append({
            "run": i + 1,
            "threat_score": result.threat_score,
            "hash": result.deterministic_hash,
            "threat_level": result.threat_level.value,
            "action": result.recommended_action.value
        })
        print(f"Run {i+1}: Score={result.threat_score:.6f}, Hash={result.deterministic_hash}")
    
    # Verify all results are identical
    first_result = results[0]
    all_identical = all(
        r["threat_score"] == first_result["threat_score"] and
        r["hash"] == first_result["hash"] and
        r["threat_level"] == first_result["threat_level"] and
        r["action"] == first_result["action"]
        for r in results
    )
    
    print(f"\n✓ All results identical: {all_identical}")
    print(f"✓ Deterministic validation: {aggregator.validate_deterministic_behavior(components, target)}")


def demonstrate_threshold_profiles():
    """Demonstrate different threshold profiles produce different recommendations."""
    
    print("\n\n=== THRESHOLD PROFILES DEMONSTRATION ===\n")
    
    components = create_sample_email_analysis()
    target = "email_suspicious_microsoft_login_2024_01_15"
    
    profiles = [
        ("Strict", strict_aggregator),
        ("Balanced", balanced_aggregator),
        ("Lenient", lenient_aggregator)
    ]
    
    print("Same email analyzed with different risk tolerance profiles:\n")
    
    for profile_name, aggregator in profiles:
        result = aggregator.aggregate_threat_scores(components, target)
        
        print(f"{profile_name} Profile:")
        print(f"  Threat Score: {result.threat_score:.3f}")
        print(f"  Threat Level: {result.threat_level.value.upper()}")
        print(f"  Recommended Action: {result.recommended_action.value.upper()}")
        print(f"  Confidence: {result.explanation.confidence_band.confidence_level:.1%}")
        print()


def demonstrate_explainability():
    """Demonstrate explainability features."""
    
    print("\n=== EXPLAINABILITY DEMONSTRATION ===\n")
    
    aggregator = balanced_aggregator
    components = create_sample_email_analysis()
    target = "email_suspicious_microsoft_login_2024_01_15"
    
    result = aggregator.aggregate_threat_scores(components, target)
    explanation = result.explanation
    
    print("THREAT ASSESSMENT EXPLANATION")
    print("=" * 50)
    print()
    
    print(f"Overall Threat Score: {result.threat_score:.3f} ({result.threat_level.value.upper()})")
    print(f"Recommended Action: {result.recommended_action.value.upper()}")
    print(f"Confidence Band: {explanation.confidence_band.lower_bound:.3f} - {explanation.confidence_band.upper_bound:.3f}")
    print(f"Confidence Level: {explanation.confidence_band.confidence_level:.1%}")
    print()
    
    print("REASONING:")
    print("-" * 20)
    print(explanation.reasoning)
    print()
    
    print("TOP CONTRIBUTING SIGNALS:")
    print("-" * 30)
    for i, signal in enumerate(explanation.top_signals[:3], 1):
        print(f"{i}. {signal.description}")
        print(f"   Component: {signal.component_type.value}")
        print(f"   Weight: {signal.weight:.3f} | Score: {signal.score:.3f} | Contribution: {signal.contribution:.4f}")
        print(f"   Evidence: {', '.join(signal.evidence[:2])}")
        print()
    
    print("COMPONENT BREAKDOWN:")
    print("-" * 25)
    total_contribution = sum(explanation.component_breakdown.values())
    for component, contribution in sorted(explanation.component_breakdown.items(), 
                                        key=lambda x: x[1], reverse=True):
        percentage = (contribution / total_contribution * 100) if total_contribution > 0 else 0
        print(f"  {component}: {contribution:.4f} ({percentage:.1f}%)")
    print()
    
    print("CERTAINTY FACTORS:")
    print("-" * 20)
    for factor, value in explanation.certainty_factors.items():
        print(f"  {factor}: {value:.3f}")
    print()
    
    print("KEY RISK FACTORS:")
    print("-" * 20)
    for risk_factor in explanation.risk_factors:
        print(f"  • {risk_factor}")
    print()
    
    print("METADATA:")
    print("-" * 10)
    print(f"  Deterministic Hash: {result.deterministic_hash}")
    print(f"  Processing Time: {result.processing_time:.3f}s")
    print(f"  Components Processed: {result.aggregation_metadata['components_processed']}")
    print(f"  Aggregation Method: {result.aggregation_metadata['aggregation_method']}")
    print(f"  Threshold Profile: {result.aggregation_metadata['threshold_profile']}")


def demonstrate_analyst_workflow():
    """Demonstrate how analysts would use the enhanced system."""
    
    print("\n\n=== ANALYST WORKFLOW DEMONSTRATION ===\n")
    
    components = create_sample_email_analysis()
    target = "email_suspicious_microsoft_login_2024_01_15"
    
    # Analyst reviews threat with balanced profile
    result = balanced_aggregator.aggregate_threat_scores(components, target)
    
    print("ANALYST DASHBOARD VIEW")
    print("=" * 30)
    print()
    
    # Quick status
    status_color = "🔴" if result.threat_level.value in ["critical", "high"] else "🟡" if result.threat_level.value == "medium" else "🟢"
    print(f"{status_color} THREAT LEVEL: {result.threat_level.value.upper()}")
    print(f"📊 THREAT SCORE: {result.threat_score:.1%}")
    print(f"🎯 RECOMMENDED ACTION: {result.recommended_action.value.upper()}")
    print(f"📈 CONFIDENCE: {result.explanation.confidence_band.confidence_level:.1%}")
    print()
    
    # Key indicators for quick scanning
    print("🚨 KEY THREAT INDICATORS:")
    for signal in result.explanation.top_signals[:3]:
        print(f"   • {signal.description}")
    print()
    
    # Component agreement for trust
    agreement = result.explanation.certainty_factors.get("component_agreement", 0)
    agreement_text = "Strong" if agreement > 0.8 else "Moderate" if agreement > 0.6 else "Weak"
    print(f"🤝 COMPONENT AGREEMENT: {agreement_text} ({agreement:.1%})")
    print()
    
    # Evidence for verification
    print("🔍 SUPPORTING EVIDENCE:")
    for signal in result.explanation.top_signals[:2]:
        print(f"   {signal.signal_name}: {', '.join(signal.evidence)}")
    print()
    
    # Reproducibility verification
    print(f"🔒 ANALYSIS HASH: {result.deterministic_hash}")
    print(f"✅ REPRODUCIBLE: Same inputs will always produce identical results")
    print()
    
    # Action guidance
    print("📋 ANALYST ACTIONS:")
    if result.recommended_action.value == "block":
        print("   1. Block sender and domain immediately")
        print("   2. Add to organization blacklist")
        print("   3. Notify affected users")
        print("   4. Document incident for training")
    elif result.recommended_action.value == "quarantine":
        print("   1. Quarantine email for review")
        print("   2. Verify with sender through alternate channel")
        print("   3. Monitor for similar patterns")
    print()


if __name__ == "__main__":
    """Run all demonstrations."""
    
    print("🚀 ENHANCED THREAT AGGREGATOR DEMONSTRATION")
    print("=" * 60)
    print("Showcasing deterministic scoring and explainability features")
    print("for analyst trust and operational consistency.")
    print()
    
    try:
        demonstrate_deterministic_scoring()
        demonstrate_threshold_profiles()
        demonstrate_explainability()
        demonstrate_analyst_workflow()
        
        print("\n" + "=" * 60)
        print("✅ DEMONSTRATION COMPLETED SUCCESSFULLY")
        print()
        print("Key benefits demonstrated:")
        print("• Deterministic scoring ensures reproducible results")
        print("• Threshold profiles adapt to organizational risk tolerance")
        print("• Structured explanations build analyst trust")
        print("• Component breakdown enables verification")
        print("• Evidence trails support decision documentation")
        
    except Exception as e:
        print(f"\n❌ DEMONSTRATION FAILED: {e}")
        import traceback
        traceback.print_exc()