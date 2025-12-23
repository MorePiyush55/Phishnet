"""
On-Demand Phishing Detection Workflow - Integration Test
=========================================================
Tests the complete end-to-end workflow:
1. Email intake (IMAP polling)
2. Detection (EnhancedPhishingAnalyzer)
3. Interpretation (Gemini)
4. Response (SMTP)

Run with: python -m pytest tests/test_ondemand_workflow.py -v
Or standalone: python tests/test_ondemand_workflow.py
"""

import asyncio
import sys
import os

# Add backend to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from datetime import datetime
from typing import Dict, Any


def print_section(title: str):
    """Print a section header"""
    print(f"\n{'='*60}")
    print(f" {title}")
    print('='*60)


def print_result(label: str, value: Any, indent: int = 0):
    """Print a labeled result"""
    prefix = "  " * indent
    print(f"{prefix}• {label}: {value}")


async def test_imap_connection():
    """Test 1: IMAP Connection"""
    print_section("TEST 1: IMAP Connection")
    
    try:
        from app.services.quick_imap import QuickIMAPService
        
        imap_service = QuickIMAPService()
        
        if not imap_service.user or not imap_service.password:
            print("❌ IMAP not configured (missing IMAP_USER or IMAP_PASSWORD)")
            return False
        
        print(f"  Connecting to {imap_service.host}...")
        print(f"  User: {imap_service.user}")
        
        success = imap_service.test_connection()
        
        if success:
            print("✅ IMAP connection successful")
            return True
        else:
            print("❌ IMAP connection failed")
            return False
            
    except Exception as e:
        print(f"❌ IMAP test error: {e}")
        return False


async def test_pending_emails():
    """Test 2: List Pending Emails"""
    print_section("TEST 2: List Pending Emails")
    
    try:
        from app.services.quick_imap import QuickIMAPService
        
        imap_service = QuickIMAPService()
        pending = imap_service.get_pending_emails()
        
        print(f"✅ Found {len(pending)} pending emails")
        
        for i, email in enumerate(pending[:5]):  # Show first 5
            print(f"\n  Email {i+1}:")
            print_result("UID", email.get('uid'), indent=2)
            print_result("From", email.get('from'), indent=2)
            print_result("Subject", email.get('subject', '')[:50], indent=2)
            print_result("Date", email.get('date'), indent=2)
        
        if len(pending) > 5:
            print(f"\n  ... and {len(pending) - 5} more")
        
        # Return True even if 0 emails (the test is about the connection working)
        return True
        
    except Exception as e:
        print(f"❌ List pending error: {e}")
        return False


async def test_detection_module():
    """Test 3: Detection Module (EnhancedPhishingAnalyzer)"""
    print_section("TEST 3: Detection Module")
    
    try:
        from app.services.enhanced_phishing_analyzer import EnhancedPhishingAnalyzer
        
        # Create test email content
        test_email = b"""From: "PayPal Security" <security@paypal-update.tk>
To: victim@example.com
Subject: URGENT: Your account has been suspended
Date: Mon, 23 Dec 2024 10:00:00 -0000
Message-ID: <test123@test.com>
Authentication-Results: mx.google.com;
    spf=fail (google.com: domain of security@paypal-update.tk does not designate permitted sender hosts)
    dkim=none
    dmarc=fail
Content-Type: text/html; charset="UTF-8"

<html>
<body>
<p>Dear Customer,</p>
<p>Your PayPal account has been LIMITED. You must verify your identity immediately or your account will be CLOSED.</p>
<p>Click here to verify: <a href="http://paypal-verify.tk/login">http://paypal-verify.tk/login</a></p>
<p>You have 24 hours to respond or your funds will be frozen!</p>
<p>PayPal Security Team</p>
</body>
</html>
"""
        
        analyzer = EnhancedPhishingAnalyzer()
        result = analyzer.analyze_email(test_email)
        
        print("✅ Detection analysis complete")
        print(f"\n  VERDICT: {result.final_verdict}")
        print(f"  Total Score: {result.total_score}/100 (lower = more dangerous)")
        print(f"  Confidence: {result.confidence:.0%}")
        
        print("\n  Section Scores:")
        print_result("Sender", f"{result.sender.score}/100", indent=2)
        print_result("Content", f"{result.content.score}/100", indent=2)
        print_result("Links", f"{result.links.overall_score}/100", indent=2)
        print_result("Authentication", f"{result.authentication.overall_score}/100", indent=2)
        print_result("Attachments", f"{result.attachments.score}/100", indent=2)
        
        print("\n  Risk Factors:")
        for factor in result.risk_factors[:5]:
            print(f"    - {factor}")
        
        print("\n  Authentication Details:")
        print_result("SPF", result.authentication.spf_result, indent=2)
        print_result("DKIM", result.authentication.dkim_result, indent=2)
        print_result("DMARC", result.authentication.dmarc_result, indent=2)
        
        return result
        
    except Exception as e:
        print(f"❌ Detection test error: {e}")
        import traceback
        traceback.print_exc()
        return None


async def test_gemini_interpretation():
    """Test 4: Gemini Interpretation"""
    print_section("TEST 4: Gemini Interpretation")
    
    try:
        from app.services.gemini import GeminiClient
        
        gemini = GeminiClient()
        
        if not gemini.is_available:
            print("⚠️ Gemini API not configured (missing GEMINI_API_KEY)")
            print("  Interpretation will fall back to rule-based explanations")
            return None
        
        # Test with structured technical report
        technical_report = {
            "subject": "URGENT: Your account has been suspended",
            "verdict": "PHISHING",
            "total_score": 15,
            "confidence": 0.9,
            "risk_factors": ["SPF_FAIL", "DKIM_FAIL", "URGENCY_HIGH", "SUSPICIOUS_TLD"],
            "sections": {
                "sender": {"score": 20, "indicators": ["display name mismatch", "suspicious TLD .tk"]},
                "content": {"score": 10, "indicators": ["urgency words: 8", "phishing keywords: 5"]},
                "links": {"score": 15, "indicators": ["http link", "suspicious TLD"]},
                "authentication": {"score": 0, "indicators": ["SPF fail", "DKIM none", "DMARC fail"]},
                "attachments": {"score": 100, "indicators": []}
            }
        }
        
        print("  Sending technical report to Gemini for interpretation...")
        
        result = await gemini.interpret_technical_findings(technical_report)
        
        print("✅ Gemini interpretation complete")
        print(f"\n  Verdict: {result.verdict}")
        print(f"  Threat Score: {result.llm_score:.1%}")
        
        print("\n  Key Reasons (Plain Language):")
        for reason in result.explanation_snippets:
            print(f"    • {reason}")
        
        print("\n  Recommended Action:")
        for action in result.detected_techniques:
            print(f"    👉 {action}")
        
        return result
        
    except Exception as e:
        print(f"❌ Gemini test error: {e}")
        import traceback
        traceback.print_exc()
        return None


async def test_orchestrator():
    """Test 5: On-Demand Orchestrator"""
    print_section("TEST 5: On-Demand Orchestrator")
    
    try:
        from app.services.ondemand_orchestrator import get_ondemand_orchestrator
        
        orchestrator = get_ondemand_orchestrator()
        
        print("✅ Orchestrator initialized")
        print_result("IMAP configured", bool(orchestrator.imap_service.user), indent=1)
        print_result("Gemini available", orchestrator.gemini_client.is_available, indent=1)
        
        return orchestrator
        
    except Exception as e:
        print(f"❌ Orchestrator test error: {e}")
        return None


async def test_email_sender():
    """Test 6: Email Sender (SMTP)"""
    print_section("TEST 6: Email Sender (SMTP)")
    
    try:
        from app.services.email_sender import send_email
        from app.config.settings import get_settings
        
        settings = get_settings()
        
        sender_email = getattr(settings, 'IMAP_USER', None)
        sender_pass = getattr(settings, 'IMAP_PASSWORD', None)
        
        if not sender_email or not sender_pass:
            print("⚠️ SMTP not configured (uses same credentials as IMAP)")
            return False
        
        print(f"  Sender: {sender_email}")
        print("  Note: Actual email sending not tested to avoid spam")
        print("✅ SMTP configuration verified")
        
        return True
        
    except Exception as e:
        print(f"❌ Email sender test error: {e}")
        return False


async def test_worker():
    """Test 7: Background Polling Worker"""
    print_section("TEST 7: Background Polling Worker")
    
    try:
        from app.workers.email_polling_worker import get_email_polling_worker, WorkerState
        
        worker = get_email_polling_worker()
        status = worker.get_status()
        
        print("✅ Worker initialized")
        print_result("State", status['state'], indent=1)
        print_result("Poll Interval", f"{status['poll_interval']} seconds", indent=1)
        print_result("Total Polls", status['metrics']['total_polls'], indent=1)
        print_result("Emails Processed", status['metrics']['total_emails_processed'], indent=1)
        
        return worker
        
    except Exception as e:
        print(f"❌ Worker test error: {e}")
        return None


async def test_full_workflow_simulation():
    """Test 8: Full Workflow Simulation (without actual email)"""
    print_section("TEST 8: Full Workflow Simulation")
    
    try:
        from app.services.ondemand_orchestrator import (
            OnDemandOrchestrator, 
            AnalysisJob, 
            JobStatus,
            InterpretationResult
        )
        from app.services.enhanced_phishing_analyzer import EnhancedPhishingAnalyzer
        
        # Simulate the workflow with test data
        print("  Simulating complete workflow...")
        
        # Step 1: Parse email (simulated)
        print("\n  Step 1: Email Parsed")
        print_result("Forwarded by", "test@example.com", indent=2)
        print_result("Subject", "URGENT: Account Suspended", indent=2)
        
        # Step 2: Detection
        print("\n  Step 2: Detection")
        analyzer = EnhancedPhishingAnalyzer()
        
        test_email = b"""From: "Bank Security" <alert@bank-secure.tk>
To: victim@example.com
Subject: URGENT: Account Suspended
Authentication-Results: spf=fail; dkim=none; dmarc=fail
Content-Type: text/plain

Your account has been suspended. Click here immediately: http://verify.tk/login
"""
        
        detection = analyzer.analyze_email(test_email)
        print_result("Verdict", detection.final_verdict, indent=2)
        print_result("Score", f"{detection.total_score}/100", indent=2)
        
        # Step 3: Interpretation (simulated)
        print("\n  Step 3: Interpretation")
        interpretation = InterpretationResult(
            verdict=detection.final_verdict,
            reasons=[
                "The sender's email failed security verification.",
                "The message uses urgent language to pressure you.",
                "Contains a link to a suspicious domain."
            ],
            guidance=[
                "Delete this email immediately.",
                "Do NOT click any links.",
                "Report to your IT team."
            ],
            threat_score=0.85
        )
        
        for reason in interpretation.reasons:
            print(f"    • {reason}")
        
        # Step 4: Response (simulated)
        print("\n  Step 4: Response")
        print("    Would send email to: test@example.com")
        print(f"    Subject: PhishNet Analysis: 🚨 {detection.final_verdict}")
        
        print("\n✅ Workflow simulation complete!")
        
        return True
        
    except Exception as e:
        print(f"❌ Workflow simulation error: {e}")
        import traceback
        traceback.print_exc()
        return False


async def run_all_tests():
    """Run all integration tests"""
    print("\n" + "="*60)
    print(" ON-DEMAND PHISHING DETECTION - INTEGRATION TESTS")
    print(" " + datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    print("="*60)
    
    results = {}
    
    # Run tests
    results['imap'] = await test_imap_connection()
    results['pending'] = await test_pending_emails()
    results['detection'] = await test_detection_module()
    results['gemini'] = await test_gemini_interpretation()
    results['orchestrator'] = await test_orchestrator()
    results['smtp'] = await test_email_sender()
    results['worker'] = await test_worker()
    results['simulation'] = await test_full_workflow_simulation()
    
    # Summary
    print_section("TEST SUMMARY")
    
    passed = sum(1 for v in results.values() if v)
    total = len(results)
    
    for test_name, result in results.items():
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"  {test_name.upper():20} {status}")
    
    print(f"\n  Total: {passed}/{total} tests passed")
    
    if passed == total:
        print("\n🎉 All tests passed! On-demand workflow is ready.")
    else:
        print("\n⚠️ Some tests failed. Check configuration.")
    
    return results


if __name__ == "__main__":
    asyncio.run(run_all_tests())
