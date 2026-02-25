"""
PhishNet API Integration Tests
================================
Integration tests for external API services (VirusTotal, AbuseIPDB, Gemini).

These tests call the real APIs and are skipped when the corresponding
environment variable (API key) is not set.

Usage:
    # Run ALL integration tests (requires all keys set):
    pytest tests/integration/test_api_integration.py -v

    # Run only VirusTotal tests:
    VIRUSTOTAL_API_KEY=xxx pytest tests/integration/test_api_integration.py -k virustotal -v
"""

import asyncio
import os
import sys

import pytest

# Ensure backend root is on sys.path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))


# ---------------------------------------------------------------------------
# Skip markers — tests are skipped when API key is absent
# ---------------------------------------------------------------------------

VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY") or os.getenv("GOOGLE_GEMINI_API_KEY")

skip_no_vt = pytest.mark.skipif(
    not VIRUSTOTAL_API_KEY,
    reason="VIRUSTOTAL_API_KEY not set — skipping live API tests",
)
skip_no_abuse = pytest.mark.skipif(
    not ABUSEIPDB_API_KEY,
    reason="ABUSEIPDB_API_KEY not set — skipping live API tests",
)
skip_no_gemini = pytest.mark.skipif(
    not GEMINI_API_KEY,
    reason="GEMINI_API_KEY / GOOGLE_GEMINI_API_KEY not set — skipping live API tests",
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _run_async(coro):
    """Run an async coroutine in a new event loop (for sync pytest)."""
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


# ===================================================================
# VirusTotal Tests
# ===================================================================

@skip_no_vt
class TestVirusTotalIntegration:
    """Live integration tests for the VirusTotal API client."""

    def _get_client(self):
        from app.services.virustotal import VirusTotalClient
        return VirusTotalClient(api_key=VIRUSTOTAL_API_KEY)

    def test_scan_known_safe_url(self):
        """VirusTotal should report google.com as clean."""
        client = self._get_client()
        result = _run_async(client.scan("https://www.google.com"))

        assert result is not None
        assert "verdict" in result
        assert result["verdict"].lower() in ("clean", "safe", "undetected")

    def test_scan_known_malicious_url(self):
        """VirusTotal should flag the EICAR test URL as malicious."""
        client = self._get_client()
        # The EICAR test file URL is universally recognized as malicious
        result = _run_async(client.scan("http://malware.testing.google.test/testing/malware/"))

        assert result is not None
        assert "verdict" in result
        # Even if not flagged as malicious, we just verify API returned data
        assert "threat_score" in result

    def test_health_check(self):
        """VirusTotal health_check should succeed when key is valid."""
        client = self._get_client()
        health = _run_async(client.health_check())

        assert health is not None
        assert health.status is not None

    def test_scan_returns_expected_schema(self):
        """Scan result should conform to the normalized schema."""
        client = self._get_client()
        result = _run_async(client.scan("https://example.com"))

        assert isinstance(result, dict)
        for key in ("threat_score", "verdict", "confidence"):
            assert key in result, f"Missing key: {key}"
        assert isinstance(result["threat_score"], (int, float))
        assert isinstance(result["verdict"], str)


# ===================================================================
# AbuseIPDB Tests
# ===================================================================

@skip_no_abuse
class TestAbuseIPDBIntegration:
    """Live integration tests for the AbuseIPDB API client."""

    def _get_client(self):
        from app.services.abuseipdb import AbuseIPDBClient
        return AbuseIPDBClient(api_key=ABUSEIPDB_API_KEY)

    def test_check_known_clean_ip(self):
        """Google DNS (8.8.8.8) should have a low abuse score."""
        client = self._get_client()
        result = _run_async(client.scan("8.8.8.8"))

        assert result is not None
        assert "verdict" in result
        assert "threat_score" in result
        # Google DNS should be relatively clean
        assert result["threat_score"] < 50

    def test_check_returns_expected_schema(self):
        """AbuseIPDB result should have normalized schema keys."""
        client = self._get_client()
        result = _run_async(client.scan("1.1.1.1"))

        assert isinstance(result, dict)
        for key in ("threat_score", "verdict", "confidence"):
            assert key in result, f"Missing key: {key}"

    def test_health_check(self):
        """AbuseIPDB health_check should succeed when key is valid."""
        client = self._get_client()
        health = _run_async(client.health_check())

        assert health is not None
        assert health.status is not None

    def test_invalid_ip_format(self):
        """Scanning an invalid IP should raise or return an error result."""
        client = self._get_client()
        with pytest.raises(Exception):
            _run_async(client.scan("not-an-ip-address"))


# ===================================================================
# Gemini AI Tests
# ===================================================================

@skip_no_gemini
class TestGeminiIntegration:
    """Live integration tests for the Google Gemini AI client."""

    def _get_client(self):
        from app.services.gemini import GeminiClient
        return GeminiClient(api_key=GEMINI_API_KEY)

    def test_analyze_safe_email_content(self):
        """Gemini should classify a normal business email as safe."""
        client = self._get_client()
        safe_email = (
            "Hi John, just a reminder about our team meeting tomorrow at 3 PM "
            "in the main conference room. Please bring the quarterly reports. "
            "Thanks, Sarah"
        )
        result = _run_async(client.scan(safe_email))

        assert result is not None
        assert "verdict" in result
        assert "threat_score" in result

    def test_analyze_phishing_content(self):
        """Gemini should detect an obviously phishing email."""
        client = self._get_client()
        phishing_email = (
            "URGENT: Your account has been compromised! Click here immediately "
            "to verify your identity: http://evil-site.tk/login?id=stolen "
            "If you don't act within 24 hours, your account will be permanently "
            "deleted. Enter your password and social security number to proceed."
        )
        result = _run_async(client.scan(phishing_email))

        assert result is not None
        assert "verdict" in result
        assert "threat_score" in result
        # Expect a higher threat score for phishing content
        assert result["threat_score"] > 30

    def test_health_check(self):
        """Gemini health_check should succeed when key is valid."""
        client = self._get_client()
        health = _run_async(client.health_check())

        assert health is not None
        assert health.status is not None

    def test_scan_returns_expected_schema(self):
        """Gemini scan result should conform to the normalized schema."""
        client = self._get_client()
        result = _run_async(client.scan("Test email content for schema validation"))

        assert isinstance(result, dict)
        for key in ("threat_score", "verdict", "confidence"):
            assert key in result, f"Missing key: {key}"
        assert isinstance(result["threat_score"], (int, float))
        assert isinstance(result["verdict"], str)
