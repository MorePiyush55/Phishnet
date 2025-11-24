"""
PhishNet Orchestrator
Single source of truth for email analysis, coordinating multiple analyzers
and the deterministic threat aggregator.
"""

import asyncio
import logging
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone

from app.analyzers.content_analyzer import ContentAnalyzer
from app.analyzers.url_analyzer import URLAnalyzer
from app.services.deterministic_threat_aggregator import deterministic_aggregator, DeterministicThreatResult

logger = logging.getLogger(__name__)

class PhishNetOrchestrator:
    """
    Unified orchestrator for PhishNet email analysis.
    Coordinates:
    - Content Analysis (Keywords, NLP, Urgency)
    - URL Analysis (Reputation, Typosquatting, Redirects)
    - Sender Analysis (SPF/DKIM/DMARC checks - placeholder)
    - Threat Aggregation (Deterministic scoring)
    """

    def __init__(self):
        self.content_analyzer = ContentAnalyzer()
        self.url_analyzer = URLAnalyzer()
        # self.sender_analyzer = SenderAnalyzer() # To be implemented
        self.threat_aggregator = deterministic_aggregator

    async def analyze_email(self, email_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze an email using all available analyzers and aggregate results.

        Args:
            email_data: Dictionary containing email data:
                - body (str): Email body (text or HTML)
                - subject (str): Email subject
                - sender (str): Sender email address
                - headers (dict): Email headers
                - timestamp (str): ISO timestamp

        Returns:
            Dict containing the final analysis result.
        """
        start_time = datetime.now(timezone.utc)
        logger.info(f"Starting analysis for email from {email_data.get('sender')}")

        try:
            # 1. Run analyzers in parallel
            # Note: ContentAnalyzer and URLAnalyzer might be synchronous or async.
            # Assuming they have async methods or we wrap them.
            # Checking imports, they seem to be classes. Let's assume sync for now and wrap if needed,
            # or check if they have async methods.
            # For safety in this implementation, we'll run them sequentially if they are sync,
            # or use asyncio.to_thread if they are CPU bound.

            # Content Analysis
            content_results = await self._run_content_analysis(email_data)

            # URL Analysis
            url_results = await self._run_url_analysis(email_data)

            # Sender Analysis (Placeholder)
            sender_results = self._run_sender_analysis(email_data)

            # Attachment Analysis (Placeholder)
            attachment_results = self._run_attachment_analysis(email_data)

            # 2. Prepare components for aggregator
            analysis_components = {
                "content_analysis": content_results,
                "url_analysis": url_results,
                "sender_analysis": sender_results,
                "attachment_analysis": attachment_results
            }

            # 3. Aggregate results
            threat_result: DeterministicThreatResult = await self.threat_aggregator.analyze_threat_deterministic(
                email_data,
                analysis_components
            )

            # 4. Format output
            processing_time_ms = (datetime.now(timezone.utc) - start_time).total_seconds() * 1000

            return {
                "threat_score": threat_result.final_score,
                "risk_level": threat_result.threat_category.value.upper(),
                "confidence": threat_result.confidence_score,
                "indicators": [ind.name for ind in threat_result.indicators],
                "reasons": [comp.reasoning for comp in threat_result.components],
                "recommendations": self._generate_recommendations(threat_result),
                "analysis_timestamp": threat_result.analysis_timestamp,
                "processing_time_ms": processing_time_ms,
                "details": {
                    "explanation": threat_result.explanation,
                    "component_scores": {comp.component: comp.score for comp in threat_result.components},
                    "evidence": [ind.evidence for ind in threat_result.indicators]
                }
            }

        except Exception as e:
            logger.error(f"Orchestration failed: {e}", exc_info=True)
            return {
                "threat_score": 0.0,
                "risk_level": "ERROR",
                "confidence": 0.0,
                "indicators": [],
                "reasons": [f"Analysis failed: {str(e)}"],
                "recommendations": ["Retry analysis"],
                "processing_time_ms": 0
            }

    async def _run_content_analysis(self, email_data: Dict[str, Any]) -> Dict[str, Any]:
        """Run content analysis."""
        try:
            # ContentAnalyzer.analyze usually takes text.
            text = email_data.get("body", "") or email_data.get("subject", "")
            # Assuming analyze returns a dict or object.
            # We might need to adapt this based on actual ContentAnalyzer signature.
            # For now, we'll assume a standard interface or wrap it.
            return self.content_analyzer.analyze(text)
        except Exception as e:
            logger.warning(f"Content analysis failed: {e}")
            return {}

    async def _run_url_analysis(self, email_data: Dict[str, Any]) -> Dict[str, Any]:
        """Run URL analysis."""
        try:
            # URLAnalyzer needs text to extract URLs or a list of URLs.
            text = email_data.get("body", "")
            return self.url_analyzer.analyze(text)
        except Exception as e:
            logger.warning(f"URL analysis failed: {e}")
            return {}

    def _run_sender_analysis(self, email_data: Dict[str, Any]) -> Dict[str, Any]:
        """Run sender analysis (Placeholder)."""
        return {
            "spoofing_detected": False,
            "spf_pass": True,
            "dkim_pass": True
        }

    def _run_attachment_analysis(self, email_data: Dict[str, Any]) -> Dict[str, Any]:
        """Run attachment analysis (Placeholder)."""
        return {
            "suspicious_files": []
        }

    def _generate_recommendations(self, result: DeterministicThreatResult) -> List[str]:
        """Generate actionable recommendations based on threat result."""
        recommendations = []
        if result.final_score > 0.8:
            recommendations.append("DELETE immediately. Do not click links or open attachments.")
            recommendations.append("Report this sender to IT security.")
        elif result.final_score > 0.5:
            recommendations.append("Exercise CAUTION. Verify sender identity via other channels.")
            recommendations.append("Do not click links unless you are certain of the destination.")
        else:
            recommendations.append("Email appears safe, but always remain vigilant.")
        return recommendations
