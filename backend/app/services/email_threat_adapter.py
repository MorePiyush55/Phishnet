"""
Email Analysis to ThreatAggregator Adapter

Converts ComprehensivePhishingAnalysis results to the format expected by ThreatAggregator,
enabling sophisticated rules-based scoring and multi-source aggregation for email analysis.
"""

from typing import Dict, Any, Optional
from dataclasses import dataclass

from app.schemas.threat_result import (
    ThreatResult, ThreatLevel, ComponentType, ComponentScore,
    AggregationConfig
)
from app.services.enhanced_phishing_analyzer import ComprehensivePhishingAnalysis
from app.config.logging import get_logger

logger = get_logger(__name__)


# Custom configuration for email threat assessment
EMAIL_AGGREGATION_CONFIG = AggregationConfig(
    component_weights={
        ComponentType.CONTENT_ANALYSIS: 0.30,  # Email content (keywords, urgency)
        ComponentType.LLM_VERDICT: 0.25,       # Gemini interpretation
        ComponentType.VIRUSTOTAL: 0.20,        # Link scanning
        ComponentType.ABUSEIPDB: 0.15,         # Sender IP reputation
        ComponentType.REPUTATION_CHECK: 0.10,  # Sender reputation (SPF/DKIM)
    },
    threat_thresholds={
        ThreatLevel.SAFE: 0.0,
        ThreatLevel.SUSPICIOUS: 0.35,
        ThreatLevel.MALICIOUS: 0.65
    },
    confidence_boost_threshold=0.80,
    rule_overrides_enabled=True,
    minimum_components=2
)


def convert_email_analysis_to_aggregator_input(
    analysis: ComprehensivePhishingAnalysis,
    gemini_result: Optional[Dict[str, Any]] = None,
    virustotal_data: Optional[Dict[str, Any]] = None,
    abuseipdb_data: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    Convert ComprehensivePhishingAnalysis to ThreatAggregator input format.
    
    Args:
        analysis: The email analysis result
        gemini_result: Optional Gemini interpretation data
        virustotal_data: Optional VirusTotal scan results
        abuseipdb_data: Optional AbuseIPDB check results
        
    Returns:
        Dictionary in ThreatAggregator input format
    """
    aggregator_input = {}
    
    # ═══════════════════════════════════════════════════════════════
    # 1. Convert email content analysis to CONTENT_ANALYSIS component
    # ═══════════════════════════════════════════════════════════════
    content_score = 1.0 - (analysis.content.score / 100.0)  # Invert: low safety = high threat
    content_features = {
        "keywords_found": len(analysis.content.phishing_keywords_found),
        "urgency_level": analysis.content.urgency_level,
        "indicators": analysis.content.indicators
    }
    
    aggregator_input["content_analysis"] = {
        "score": content_score,
        "features": content_features,
        "confidence": 0.85,
        "reasoning": f"Found {len(analysis.content.phishing_keywords_found)} phishing keywords, urgency: {analysis.content.urgency_level}"
    }
    
    # ═══════════════════════════════════════════════════════════════
    # 2. Convert sender + auth analysis to REPUTATION_CHECK component  
    # ═══════════════════════════════════════════════════════════════
    # Combine sender and authentication scores
    sender_threat = 1.0 - (analysis.sender.score / 100.0)
    auth_threat = 1.0 - (analysis.authentication.overall_score / 100.0)
    reputation_score = (sender_threat * 0.6) + (auth_threat * 0.4)
    
    reputation_features = {
        "sender_indicators": analysis.sender.indicators,
        "spf_result": analysis.authentication.spf_result,
        "dkim_result": analysis.authentication.dkim_result,
        "dmarc_result": analysis.authentication.dmarc_result,
        "email_address": analysis.sender.email_address,
        "display_name": analysis.sender.display_name
    }
    
    aggregator_input["reputation_check"] = {
        "score": reputation_score,
        "features": reputation_features,
        "confidence": 0.80,
        "reasoning": f"SPF: {analysis.authentication.spf_result}, DKIM: {analysis.authentication.dkim_result}"
    }
    
    # ═══════════════════════════════════════════════════════════════
    # 3. Add Gemini LLM verdict if available
    # ═══════════════════════════════════════════════════════════════
    if gemini_result:
        aggregator_input["llm_analysis"] = {
            "verdict": gemini_result.get("verdict", "unknown"),
            "reasoning": gemini_result.get("explanation", ""),
            "confidence": gemini_result.get("confidence", 0.7),
            "raw_response": gemini_result
        }
    
    # ═══════════════════════════════════════════════════════════════
    # 4. Add VirusTotal results if available
    # ═══════════════════════════════════════════════════════════════
    if virustotal_data:
        aggregator_input["virustotal"] = {
            "positives": virustotal_data.get("positives", 0),
            "total": virustotal_data.get("total", 0),
            "scan_date": virustotal_data.get("scan_date", ""),
            "permalink": virustotal_data.get("permalink", "")
        }
    elif analysis.links.total_links > 0:
        # Create synthetic VT data from link analysis
        suspicious_links = analysis.links.encoded_links + analysis.links.redirect_links
        aggregator_input["virustotal"] = {
            "positives": min(suspicious_links, 5),  # Cap at 5
            "total": analysis.links.total_links,
            "scan_date": "",
            "permalink": ""
        }
    
    # ═══════════════════════════════════════════════════════════════
    # 5. Add AbuseIPDB results if available
    # ═══════════════════════════════════════════════════════════════
    if abuseipdb_data:
        aggregator_input["abuseipdb"] = {
            "abuse_confidence": abuseipdb_data.get("abuse_confidence", 0),
            "usage_type": abuseipdb_data.get("usage_type", ""),
            "isp": abuseipdb_data.get("isp", ""),
            "country": abuseipdb_data.get("country", ""),
            "is_whitelisted": abuseipdb_data.get("is_whitelisted", False)
        }
    elif analysis.sender.sender_ip:
        # Create placeholder for sender IP check
        aggregator_input["abuseipdb"] = {
            "abuse_confidence": 0,
            "usage_type": "unknown",
            "isp": "",
            "country": "",
            "is_whitelisted": False
        }
    
    # ═══════════════════════════════════════════════════════════════
    # 6. Add redirect/link analysis
    # ═══════════════════════════════════════════════════════════════
    if analysis.links.total_links > 0:
        # Convert link analysis to redirect analysis format
        redirect_chain = []
        for link in analysis.links.link_details[:5]:
            redirect_chain.append({
                "url": link.get("url", ""),
                "is_redirect": link.get("is_redirect", False),
                "is_encoded": link.get("is_encoded", False)
            })
        
        suspicious_patterns = []
        if analysis.links.http_links > 0:
            suspicious_patterns.append("http_links_found")
        if analysis.links.encoded_links > 0:
            suspicious_patterns.append("encoded_urls")
        if analysis.links.redirect_links > 0:
            suspicious_patterns.append("redirect_urls")
        if analysis.links.suspicious_tlds:
            suspicious_patterns.append("suspicious_tld")
        
        aggregator_input["redirect_analysis"] = {
            "redirect_chain": redirect_chain,
            "suspicious_patterns": suspicious_patterns,
            "cloaking_detected": len(suspicious_patterns) >= 3,
            "final_url": redirect_chain[-1]["url"] if redirect_chain else ""
        }
    
    return aggregator_input


async def aggregate_email_threat(
    analysis: ComprehensivePhishingAnalysis,
    gemini_result: Optional[Dict[str, Any]] = None,
    virustotal_data: Optional[Dict[str, Any]] = None,
    abuseipdb_data: Optional[Dict[str, Any]] = None,
    email_id: Optional[str] = None
) -> ThreatResult:
    """
    Run full threat aggregation on email analysis results.
    
    Args:
        analysis: The email analysis result
        gemini_result: Optional Gemini interpretation
        virustotal_data: Optional VirusTotal results
        abuseipdb_data: Optional AbuseIPDB results
        email_id: Optional email identifier
        
    Returns:
        ThreatResult with aggregated assessment
    """
    from app.services.aggregator import ThreatAggregator
    
    # Convert to aggregator input format
    aggregator_input = convert_email_analysis_to_aggregator_input(
        analysis=analysis,
        gemini_result=gemini_result,
        virustotal_data=virustotal_data,
        abuseipdb_data=abuseipdb_data
    )
    
    # Create aggregator with email-specific config
    aggregator = ThreatAggregator(config=EMAIL_AGGREGATION_CONFIG)
    
    # Get email identifier
    target_email = email_id or analysis.sender.email_address or "unknown_email"
    
    try:
        # Run aggregation
        result = await aggregator.aggregate_threat_assessment(
            target=target_email,
            target_type="email",
            analysis_results=aggregator_input,
            config_override=EMAIL_AGGREGATION_CONFIG
        )
        
        logger.info(
            f"ThreatAggregator result: score={result.score:.2f}, "
            f"level={result.level.value}, confidence={result.confidence:.2f}"
        )
        
        return result
        
    except Exception as e:
        logger.error(f"ThreatAggregator failed: {e}")
        raise


def threat_result_to_verdict(result: ThreatResult) -> str:
    """Convert ThreatResult level to PhishNet verdict string."""
    level_to_verdict = {
        ThreatLevel.SAFE: "SAFE",
        ThreatLevel.SUSPICIOUS: "SUSPICIOUS",
        ThreatLevel.MALICIOUS: "PHISHING"
    }
    return level_to_verdict.get(result.level, "SUSPICIOUS")


def enrich_analysis_with_aggregation(
    analysis: ComprehensivePhishingAnalysis,
    threat_result: ThreatResult
) -> ComprehensivePhishingAnalysis:
    """
    Enrich the original analysis with ThreatAggregator insights.
    
    Modifies analysis in-place with:
    - Updated verdict based on rules engine
    - Additional risk factors from aggregation
    - Confidence adjustment
    """
    # Update verdict if aggregator found something the base analysis missed
    aggregated_verdict = threat_result_to_verdict(threat_result)
    
    # Only upgrade verdict (never downgrade for safety)
    verdict_severity = {"SAFE": 0, "SUSPICIOUS": 1, "PHISHING": 2}
    current_severity = verdict_severity.get(analysis.final_verdict, 0)
    aggregated_severity = verdict_severity.get(aggregated_verdict, 0)
    
    if aggregated_severity > current_severity:
        logger.info(
            f"ThreatAggregator upgraded verdict: {analysis.final_verdict} → {aggregated_verdict}"
        )
        analysis.final_verdict = aggregated_verdict
        analysis.confidence = max(analysis.confidence, threat_result.confidence)
    
    # Add aggregator insights to risk factors
    for reason in threat_result.explanation.primary_reasons[:3]:
        if reason not in analysis.risk_factors:
            analysis.risk_factors.append(f"[Aggregator] {reason}")
    
    # Add rule override information if any
    for override in threat_result.rule_overrides:
        if override.triggered:
            analysis.risk_factors.append(
                f"🚨 Rule Override: {override.rule_name} - {override.explanation}"
            )
    
    return analysis
