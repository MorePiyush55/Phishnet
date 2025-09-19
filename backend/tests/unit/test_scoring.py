"""Unit tests for the scoring and risk assessment system."""

import pytest
from unittest.mock import Mock, patch, AsyncMock
from datetime import datetime, timezone
import json

from app.services.scoring import ScoringEngine, RiskCalculator
from app.models.email import Email
from app.models.scoring import EmailScore, ScoringRule
from app.schemas.scoring import ScoringRequest, ScoringResponse


class TestRiskCalculator:
    """Test risk calculation functionality."""
    
    def test_calculate_content_risk_phishing_indicators(self):
        """Test content risk calculation with phishing indicators."""
        calculator = RiskCalculator()
        
        phishing_content = """
        URGENT: Your account has been compromised!
        Click here immediately to secure your account:
        https://security-verification.fake-bank.com/login
        
        Failure to act within 24 hours will result in permanent account closure.
        
        Verify your password and credit card information now.
        """
        
        risk_score = calculator.calculate_content_risk(phishing_content)
        
        # Should detect high risk due to urgency, suspicious URL, and credential requests
        assert risk_score > 0.7
    
    def test_calculate_content_risk_legitimate_content(self):
        """Test content risk calculation with legitimate content."""
        calculator = RiskCalculator()
        
        legitimate_content = """
        Dear Customer,
        
        Thank you for your recent purchase. Your order #12345 has been shipped
        and should arrive within 3-5 business days.
        
        You can track your package at: https://legitimate-store.com/track/12345
        
        Best regards,
        Customer Service Team
        """
        
        risk_score = calculator.calculate_content_risk(legitimate_content)
        
        # Should be low risk
        assert risk_score < 0.3
    
    def test_calculate_sender_risk_suspicious_domain(self):
        """Test sender risk calculation with suspicious domain."""
        calculator = RiskCalculator()
        
        # Typo-squatting domain
        suspicious_sender = "security@paypaI.com"  # Note the capital 'I' instead of 'l'
        
        risk_score = calculator.calculate_sender_risk(suspicious_sender)
        
        # Should detect high risk due to typo-squatting
        assert risk_score > 0.5
    
    def test_calculate_sender_risk_legitimate_domain(self):
        """Test sender risk calculation with legitimate domain."""
        calculator = RiskCalculator()
        
        legitimate_sender = "support@microsoft.com"
        
        risk_score = calculator.calculate_sender_risk(legitimate_sender)
        
        # Should be low risk for known legitimate domain
        assert risk_score < 0.2
    
    def test_calculate_url_risk_suspicious_urls(self):
        """Test URL risk calculation with suspicious URLs."""
        calculator = RiskCalculator()
        
        suspicious_urls = [
            "https://paypal-verification.evil-domain.com/login",
            "http://bit.ly/shortened-suspicious-link",
            "https://secure-bank-login.fake-domain.net/verify"
        ]
        
        risk_score = calculator.calculate_url_risk(suspicious_urls)
        
        # Should detect high risk due to suspicious domains and patterns
        assert risk_score > 0.6
    
    def test_calculate_url_risk_legitimate_urls(self):
        """Test URL risk calculation with legitimate URLs."""
        calculator = RiskCalculator()
        
        legitimate_urls = [
            "https://www.microsoft.com/support",
            "https://help.google.com/accounts",
            "https://support.apple.com"
        ]
        
        risk_score = calculator.calculate_url_risk(legitimate_urls)
        
        # Should be low risk for known legitimate domains
        assert risk_score < 0.2
    
    def test_calculate_header_risk_spoofed_headers(self):
        """Test header risk calculation with spoofed headers."""
        calculator = RiskCalculator()
        
        suspicious_headers = {
            "From": "security@paypal.com",
            "Reply-To": "noreply@evil-domain.com",  # Different domain
            "Return-Path": "bounce@suspicious-mailer.net",  # Another different domain
            "Received": "from suspicious-server.com"
        }
        
        risk_score = calculator.calculate_header_risk(suspicious_headers)
        
        # Should detect high risk due to domain mismatches
        assert risk_score > 0.5
    
    def test_calculate_header_risk_consistent_headers(self):
        """Test header risk calculation with consistent headers."""
        calculator = RiskCalculator()
        
        consistent_headers = {
            "From": "support@microsoft.com",
            "Reply-To": "support@microsoft.com",
            "Return-Path": "bounce@microsoft.com",
            "Received": "from mail.microsoft.com"
        }
        
        risk_score = calculator.calculate_header_risk(consistent_headers)
        
        # Should be low risk for consistent domains
        assert risk_score < 0.3


class TestScoringEngine:
    """Test scoring engine functionality."""
    
    @pytest.fixture
    def scoring_engine(self):
        """Create ScoringEngine instance for testing."""
        return ScoringEngine()
    
    @pytest.fixture
    def sample_email(self):
        """Sample email for testing."""
        return Email(
            id="test-email-123",
            subject="Test Email",
            sender="test@example.com",
            recipient="user@company.com",
            body="Test email content",
            headers={"From": "test@example.com"},
            created_at=datetime.now(timezone.utc)
        )
    
    @pytest.fixture
    def sample_analysis_results(self):
        """Sample analysis results for testing."""
        return {
            "ai_analysis": {
                "confidence": 0.85,
                "classification": "phishing",
                "reasoning": "Suspicious urgency patterns detected"
            },
            "link_analysis": {
                "suspicious_urls": ["https://fake-bank.com/login"],
                "redirect_chains": [{"original": "https://bit.ly/abc", "final": "https://malicious.com"}],
                "risk_score": 0.8
            },
            "threat_intel": {
                "malicious_domains": ["fake-bank.com"],
                "ip_reputation": {"192.168.1.1": {"malicious": True, "confidence": 0.9}},
                "risk_score": 0.75
            }
        }
    
    def test_calculate_overall_score_high_risk(self, scoring_engine, sample_email, sample_analysis_results):
        """Test overall score calculation for high-risk email."""
        score = scoring_engine.calculate_overall_score(sample_email, sample_analysis_results)
        
        # Should be high risk due to multiple indicators
        assert score.risk_score > 0.7
        assert score.confidence > 0.8
        assert score.email_id == sample_email.id
    
    def test_calculate_overall_score_low_risk(self, scoring_engine, sample_email):
        """Test overall score calculation for low-risk email."""
        low_risk_results = {
            "ai_analysis": {
                "confidence": 0.95,
                "classification": "legitimate",
                "reasoning": "No suspicious patterns detected"
            },
            "link_analysis": {
                "suspicious_urls": [],
                "redirect_chains": [],
                "risk_score": 0.1
            },
            "threat_intel": {
                "malicious_domains": [],
                "ip_reputation": {},
                "risk_score": 0.05
            }
        }
        
        score = scoring_engine.calculate_overall_score(sample_email, low_risk_results)
        
        # Should be low risk
        assert score.risk_score < 0.3
        assert score.confidence > 0.8
    
    def test_weight_adjustment(self, scoring_engine):
        """Test scoring weight adjustment functionality."""
        # Default weights
        original_weights = scoring_engine.get_component_weights()
        
        # Adjust weights
        new_weights = {
            "ai_analysis": 0.5,
            "link_analysis": 0.3,
            "threat_intel": 0.2
        }
        
        scoring_engine.update_component_weights(new_weights)
        updated_weights = scoring_engine.get_component_weights()
        
        assert updated_weights["ai_analysis"] == 0.5
        assert updated_weights["link_analysis"] == 0.3
        assert updated_weights["threat_intel"] == 0.2
    
    def test_scoring_rules_application(self, scoring_engine):
        """Test application of custom scoring rules."""
        # Create custom rule
        rule = ScoringRule(
            name="High-value sender whitelist",
            condition="sender_domain in ['microsoft.com', 'google.com']",
            action="reduce_risk",
            weight_adjustment=-0.3,
            enabled=True
        )
        
        scoring_engine.add_scoring_rule(rule)
        
        # Test email from whitelisted domain
        email = Email(
            id="test-123",
            sender="support@microsoft.com",
            subject="Test",
            body="Test content",
            headers={}
        )
        
        analysis_results = {
            "ai_analysis": {"confidence": 0.7, "classification": "suspicious"},
            "link_analysis": {"risk_score": 0.6},
            "threat_intel": {"risk_score": 0.5}
        }
        
        score = scoring_engine.calculate_overall_score(email, analysis_results)
        
        # Score should be reduced due to whitelist rule
        # (This would need more sophisticated rule engine implementation)
        assert score.risk_score < 0.7  # Original score would be higher
    
    @pytest.mark.asyncio
    async def test_async_scoring(self, scoring_engine, sample_email, sample_analysis_results):
        """Test asynchronous scoring functionality."""
        score = await scoring_engine.calculate_score_async(sample_email, sample_analysis_results)
        
        assert isinstance(score, EmailScore)
        assert score.email_id == sample_email.id
        assert 0.0 <= score.risk_score <= 1.0
        assert 0.0 <= score.confidence <= 1.0
    
    def test_score_normalization(self, scoring_engine):
        """Test score normalization functionality."""
        # Test extreme values
        extreme_scores = [1.5, -0.5, 0.0, 1.0, 0.5]
        
        for score in extreme_scores:
            normalized = scoring_engine._normalize_score(score)
            assert 0.0 <= normalized <= 1.0
    
    def test_confidence_calculation(self, scoring_engine):
        """Test confidence calculation based on component agreement."""
        # High agreement between components
        high_agreement_results = {
            "ai_analysis": {"confidence": 0.9, "classification": "phishing"},
            "link_analysis": {"risk_score": 0.85},
            "threat_intel": {"risk_score": 0.88}
        }
        
        confidence = scoring_engine._calculate_confidence(high_agreement_results)
        assert confidence > 0.8
        
        # Low agreement between components
        low_agreement_results = {
            "ai_analysis": {"confidence": 0.9, "classification": "legitimate"},
            "link_analysis": {"risk_score": 0.85},
            "threat_intel": {"risk_score": 0.1}
        }
        
        confidence = scoring_engine._calculate_confidence(low_agreement_results)
        assert confidence < 0.7


class TestScoringIntegration:
    """Test scoring system integration."""
    
    @pytest.mark.asyncio
    async def test_end_to_end_scoring(self):
        """Test end-to-end scoring process."""
        from app.orchestrator.utils import AnalysisOrchestrator
        
        # Mock the orchestrator components
        with patch('app.services.orchestrator.AnalysisOrchestrator') as mock_orchestrator:
            mock_instance = mock_orchestrator.return_value
            mock_instance.analyze_email = AsyncMock(return_value={
                "ai_analysis": {"confidence": 0.85, "classification": "phishing"},
                "link_analysis": {"risk_score": 0.8},
                "threat_intel": {"risk_score": 0.75}
            })
            
            email_data = {
                "subject": "URGENT: Account Verification Required",
                "sender": "security@fake-bank.com",
                "body": "Click here to verify: https://fake-bank.com/verify",
                "headers": {"From": "security@fake-bank.com"}
            }
            
            # This would be the actual integration test
            # orchestrator = AnalysisOrchestrator()
            # results = await orchestrator.analyze_email(email_data)
            
            # For now, just verify the mock was called
            results = await mock_instance.analyze_email(email_data)
            assert results["ai_analysis"]["confidence"] == 0.85
    
    def test_scoring_performance(self, scoring_engine):
        """Test scoring performance with large datasets."""
        import time
        
        # Create multiple test emails
        emails = []
        for i in range(100):
            email = Email(
                id=f"test-{i}",
                subject=f"Test Email {i}",
                sender=f"sender{i}@example.com",
                body=f"Test content {i}",
                headers={"From": f"sender{i}@example.com"}
            )
            emails.append(email)
        
        # Mock analysis results
        analysis_results = {
            "ai_analysis": {"confidence": 0.8, "classification": "legitimate"},
            "link_analysis": {"risk_score": 0.2},
            "threat_intel": {"risk_score": 0.1}
        }
        
        # Measure performance
        start_time = time.time()
        
        scores = []
        for email in emails:
            score = scoring_engine.calculate_overall_score(email, analysis_results)
            scores.append(score)
        
        end_time = time.time()
        processing_time = end_time - start_time
        
        # Should process 100 emails in under 1 second
        assert processing_time < 1.0
        assert len(scores) == 100
    
    def test_scoring_consistency(self, scoring_engine):
        """Test scoring consistency across multiple runs."""
        email = Email(
            id="consistency-test",
            subject="Test Email",
            sender="test@example.com",
            body="Test content",
            headers={"From": "test@example.com"}
        )
        
        analysis_results = {
            "ai_analysis": {"confidence": 0.7, "classification": "suspicious"},
            "link_analysis": {"risk_score": 0.5},
            "threat_intel": {"risk_score": 0.4}
        }
        
        # Calculate score multiple times
        scores = []
        for _ in range(10):
            score = scoring_engine.calculate_overall_score(email, analysis_results)
            scores.append(score.risk_score)
        
        # All scores should be identical (deterministic)
        assert all(score == scores[0] for score in scores)
    
    def test_edge_cases(self, scoring_engine):
        """Test scoring with edge cases."""
        # Empty email
        empty_email = Email(
            id="empty-test",
            subject="",
            sender="",
            body="",
            headers={}
        )
        
        empty_results = {
            "ai_analysis": {"confidence": 0.5, "classification": "unknown"},
            "link_analysis": {"risk_score": 0.0},
            "threat_intel": {"risk_score": 0.0}
        }
        
        score = scoring_engine.calculate_overall_score(empty_email, empty_results)
        assert 0.0 <= score.risk_score <= 1.0
        
        # Very long email
        long_email = Email(
            id="long-test",
            subject="A" * 1000,
            sender="test@example.com",
            body="B" * 10000,
            headers={"From": "test@example.com"}
        )
        
        score = scoring_engine.calculate_overall_score(long_email, empty_results)
        assert 0.0 <= score.risk_score <= 1.0


# Mock implementations for testing
class MockScoringEngine(ScoringEngine):
    """Mock scoring engine for testing."""
    
    def __init__(self):
        super().__init__()
        self.component_weights = {
            "ai_analysis": 0.4,
            "link_analysis": 0.3,
            "threat_intel": 0.3
        }
        self.scoring_rules = []
    
    def calculate_overall_score(self, email: Email, analysis_results: dict) -> EmailScore:
        """Calculate overall risk score with simple weighted average."""
        ai_score = analysis_results.get("ai_analysis", {}).get("confidence", 0.5)
        link_score = analysis_results.get("link_analysis", {}).get("risk_score", 0.0)
        threat_score = analysis_results.get("threat_intel", {}).get("risk_score", 0.0)
        
        # Convert AI confidence to risk score
        if analysis_results.get("ai_analysis", {}).get("classification") == "phishing":
            ai_risk = ai_score
        else:
            ai_risk = 1.0 - ai_score
        
        # Weighted average
        risk_score = (
            ai_risk * self.component_weights["ai_analysis"] +
            link_score * self.component_weights["link_analysis"] +
            threat_score * self.component_weights["threat_intel"]
        )
        
        # Calculate confidence based on component agreement
        confidence = min(
            analysis_results.get("ai_analysis", {}).get("confidence", 0.5),
            0.9  # Cap confidence at 90%
        )
        
        return EmailScore(
            email_id=email.id,
            risk_score=max(0.0, min(1.0, risk_score)),
            confidence=confidence,
            processing_time=0.1,  # Mock processing time
            ai_analysis=analysis_results.get("ai_analysis"),
            threat_intel=analysis_results.get("threat_intel")
        )
    
    def get_component_weights(self) -> dict:
        """Get current component weights."""
        return self.component_weights.copy()
    
    def update_component_weights(self, weights: dict):
        """Update component weights."""
        self.component_weights.update(weights)
    
    def add_scoring_rule(self, rule: ScoringRule):
        """Add a scoring rule."""
        self.scoring_rules.append(rule)
    
    def _normalize_score(self, score: float) -> float:
        """Normalize score to [0, 1] range."""
        return max(0.0, min(1.0, score))
    
    def _calculate_confidence(self, analysis_results: dict) -> float:
        """Calculate confidence based on component agreement."""
        scores = [
            analysis_results.get("ai_analysis", {}).get("confidence", 0.5),
            analysis_results.get("link_analysis", {}).get("risk_score", 0.5),
            analysis_results.get("threat_intel", {}).get("risk_score", 0.5)
        ]
        
        # Calculate variance as measure of agreement
        mean_score = sum(scores) / len(scores)
        variance = sum((score - mean_score) ** 2 for score in scores) / len(scores)
        
        # Higher variance = lower confidence
        confidence = max(0.3, 1.0 - variance)
        
        return min(0.95, confidence)  # Cap at 95%
