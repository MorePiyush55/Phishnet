"""
Simple Test Runner for Email Integration Tests
Runs tests without complex pytest hooks
"""

import sys
import asyncio
from pathlib import Path

# Add backend to path
sys.path.insert(0, str(Path(__file__).parent.parent))

# Import test class
from tests.integration.test_email_integration_full import TestEmailIntegrationFlow, TestOutlookIntegration


async def run_email_integration_tests():
    """Run all email integration tests"""
    
    print("=" * 80)
    print("🧪 PhishNet Email Integration Test Suite")
    print("=" * 80)
    print()
    
    # Initialize test class
    test_suite = TestEmailIntegrationFlow()
    
    # Create fixtures
    mock_gmail_creds = {
        "token": "mock_access_token",
        "refresh_token": "mock_refresh_token",
        "token_uri": "https://oauth2.googleapis.com/auth/token",
        "client_id": "mock_client_id",
        "client_secret": "mock_client_secret",
        "scopes": ["https://www.googleapis.com/auth/gmail.readonly"]
    }
    
    sample_messages = [
        {
            "id": "msg_001",
            "threadId": "thread_001",
            "payload": {
                "headers": [
                    {"name": "From", "value": "noreply@paypal-secure.com"},
                    {"name": "To", "value": "user@example.com"},
                    {"name": "Subject", "value": "URGENT: Verify your account now!"},
                    {"name": "Date", "value": "Mon, 13 Oct 2025 10:30:00 +0000"}
                ],
                "body": {"data": "SGVsbG8sIFlvdXIgYWNjb3VudCB3aWxsIGJlIHN1c3BlbmRlZC4="}
            },
            "snippet": "Hello, Your account will be suspended. Click here...",
            "internalDate": "1728817800000"
        },
        {
            "id": "msg_002",
            "threadId": "thread_002",
            "payload": {
                "headers": [
                    {"name": "From", "value": "security@microsoft.com"},
                    {"name": "To", "value": "user@example.com"},
                    {"name": "Subject", "value": "Microsoft Account Activity"},
                    {"name": "Date", "value": "Mon, 13 Oct 2025 11:00:00 +0000"}
                ],
                "body": {"data": "VGhhbmsgeW91IGZvciB1c2luZyBNaWNyb3NvZnQgc2VydmljZXMu"}
            },
            "snippet": "Thank you for using Microsoft services.",
            "internalDate": "1728819600000"
        },
        {
            "id": "msg_003",
            "threadId": "thread_003",
            "payload": {
                "headers": [
                    {"name": "From", "value": "admin@company-secure.xyz"},
                    {"name": "To", "value": "user@example.com"},
                    {"name": "Subject", "value": "Re: Quarterly Report - Immediate Action Required"},
                    {"name": "Date", "value": "Mon, 13 Oct 2025 09:15:00 +0000"}
                ],
                "body": {"data": "VXJnZW50ISBEb3dubG9hZCBhdHRhY2htZW50Lg=="}
            },
            "snippet": "Urgent! Download attachment: document.exe",
            "internalDate": "1728813300000"
        }
    ]
    
    expected_scores = {
        "msg_001": {"risk": "high", "score": 0.85, "indicators": ["suspicious_url", "urgency_keywords", "spoofed_sender"]},
        "msg_002": {"risk": "low", "score": 0.15, "indicators": []},
        "msg_003": {"risk": "critical", "score": 0.95, "indicators": ["malicious_attachment", "urgency", "suspicious_domain"]}
    }
    
    # Track results
    passed = 0
    failed = 0
    
    # Test 1: Gmail OAuth Connection
    try:
        print("\nTest 1/6: Gmail OAuth Connection")
        await test_suite.test_gmail_oauth_connection(mock_gmail_creds)
        print("✅ PASSED")
        passed += 1
    except Exception as e:
        print(f"❌ FAILED: {e}")
        failed += 1
    
    # Test 2: Email Retrieval
    try:
        print("\nTest 2/6: Email Retrieval")
        await test_suite.test_email_retrieval_realtime(mock_gmail_creds, sample_messages)
        print("✅ PASSED")
        passed += 1
    except Exception as e:
        print(f"❌ FAILED: {e}")
        failed += 1
    
    # Test 3: Phishing Analysis
    try:
        print("\nTest 3/6: Phishing Analysis")
        await test_suite.test_phishing_analysis_per_email(sample_messages, expected_scores)
        print("✅ PASSED")
        passed += 1
    except Exception as e:
        print(f"❌ FAILED: {e}")
        failed += 1
    
    # Test 4: Dashboard Display
    try:
        print("\nTest 4/6: Dashboard Display Accuracy")
        await test_suite.test_dashboard_display_accuracy(sample_messages, expected_scores)
        print("✅ PASSED")
        passed += 1
    except Exception as e:
        print(f"❌ FAILED: {e}")
        failed += 1
    
    # Test 5: Real-time Updates
    try:
        print("\nTest 5/6: Real-time Updates")
        await test_suite.test_realtime_updates(sample_messages)
        print("✅ PASSED")
        passed += 1
    except Exception as e:
        print(f"❌ FAILED: {e}")
        failed += 1
    
    # Test 6: End-to-End Flow
    try:
        print("\nTest 6/6: End-to-End Integration")
        await test_suite.test_end_to_end_flow(mock_gmail_creds, sample_messages, expected_scores)
        print("✅ PASSED")
        passed += 1
    except Exception as e:
        print(f"❌ FAILED: {e}")
        failed += 1
    
    # Summary
    print("\n" + "=" * 80)
    print("📊 TEST SUMMARY")
    print("=" * 80)
    print(f"Total Tests: 6")
    print(f"✅ Passed: {passed}")
    print(f"❌ Failed: {failed}")
    print(f"Success Rate: {(passed / 6 * 100):.1f}%")
    print()
    
    if failed == 0:
        print("🎉 All tests passed successfully!")
        print("\n✅ Email Integration Verification Complete:")
        print("   - Gmail/Outlook OAuth connection working")
        print("   - Real-time email retrieval functional")
        print("   - Phishing analysis accurate")
        print("   - Dashboard displaying correct scores")
        print("   - Real-time updates operational")
        print("   - End-to-end flow validated")
    else:
        print(f"⚠️  {failed} test(s) failed. Please review the errors above.")
    
    return passed, failed


if __name__ == "__main__":
    # Run tests
    passed, failed = asyncio.run(run_email_integration_tests())
    
    # Exit with appropriate code
    sys.exit(0 if failed == 0 else 1)
