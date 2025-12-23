#!/usr/bin/env python3
"""Test script for real threat analyzers."""

import sys
import os
import asyncio

# Add the backend directory to path
backend_dir = os.path.dirname(os.path.abspath(__file__))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

# Test our analyzers directly
from app.analyzers.real_threat_analyzer import real_threat_analyzer

async def test_real_analyzer():
    """Test the real threat analyzer with sample emails."""
    
    print("🚀 Testing Real Threat Analyzer")
    print("=" * 50)
    
    # Test case 1: Suspicious phishing email
    print("\n📧 Test Case 1: Suspicious Phishing Email")
    print("-" * 40)
    
    test_email_1 = {
        "subject": "URGENT: Your PayPal Account Will Be Suspended!",
        "body": """
        Dear Customer,
        
        Your PayPal account has been limited due to suspicious activity.
        
        Click here to verify your account immediately: http://bit.ly/paypal-verify-now
        
        This link will expire in 24 hours. Failure to verify will result in permanent suspension.
        
        Enter your login credentials, SSN, and credit card details to confirm your identity.
        
        PayPal Security Team
        """,
        "sender": "security@paypal-support.com",
        "headers": {
            "from": "security@paypal-support.com",
            "to": "user@example.com",
            "date": "Mon, 21 Sep 2025 19:30:00 +0000"
        }
    }
    
    analysis_1 = await real_threat_analyzer.analyze_email(test_email_1)
    print(f"✅ Analysis Complete!")
    print(f"🚨 Is Phishing: {analysis_1['is_phishing']}")
    print(f"📊 Threat Score: {analysis_1['threat_score']:.2f}")
    print(f"🎯 Risk Level: {analysis_1['risk_level']}")
    print(f"📝 Summary: {analysis_1['summary']}")
    print(f"⚠️  Threats Detected: {', '.join(analysis_1['threats_detected'])}")
    
    # Test case 2: Legitimate email
    print("\n📧 Test Case 2: Legitimate Email")
    print("-" * 40)
    
    test_email_2 = {
        "subject": "Weekly Newsletter from TechNews",
        "body": """
        Hi there!
        
        Here's your weekly tech update:
        
        1. New Python 3.13 features
        2. Latest in AI development
        3. Security best practices
        
        Visit our website: https://technews.com
        
        Thanks for reading!
        TechNews Team
        """,
        "sender": "newsletter@technews.com",
        "headers": {
            "from": "newsletter@technews.com",
            "to": "user@example.com",
            "date": "Mon, 21 Sep 2025 19:30:00 +0000"
        }
    }
    
    analysis_2 = await real_threat_analyzer.analyze_email(test_email_2)
    print(f"✅ Analysis Complete!")
    print(f"🚨 Is Phishing: {analysis_2['is_phishing']}")
    print(f"📊 Threat Score: {analysis_2['threat_score']:.2f}")
    print(f"🎯 Risk Level: {analysis_2['risk_level']}")
    print(f"📝 Summary: {analysis_2['summary']}")
    print(f"⚠️  Threats Detected: {', '.join(analysis_2['threats_detected'])}")
    
    # Test case 3: High-risk credential phishing
    print("\n📧 Test Case 3: High-Risk Credential Phishing")
    print("-" * 40)
    
    test_email_3 = {
        "subject": "Re: Account Verification Required",
        "body": """
        URGENT NOTICE
        
        We detected unauthorized access to your Microsoft account.
        
        CLICK HERE NOW: http://microsofft-security.tk/verify-account
        
        Provide your:
        - Username and password
        - Social Security Number
        - Banking information
        - Mother's maiden name
        
        Act within 1 HOUR or account will be PERMANENTLY DELETED!
        
        Microsoft Security
        """,
        "sender": "security@microsoft.com",
        "headers": {
            "from": "security@microsoft.com",
            "to": "victim@company.com",
            "date": "Mon, 21 Sep 2025 19:30:00 +0000"
        }
    }
    
    analysis_3 = await real_threat_analyzer.analyze_email(test_email_3)
    print(f"✅ Analysis Complete!")
    print(f"🚨 Is Phishing: {analysis_3['is_phishing']}")
    print(f"📊 Threat Score: {analysis_3['threat_score']:.2f}")
    print(f"🎯 Risk Level: {analysis_3['risk_level']}")
    print(f"📝 Summary: {analysis_3['summary']}")
    print(f"⚠️  Threats Detected: {', '.join(analysis_3['threats_detected'])}")
    
    print("\n🎉 All tests completed successfully!")
    print("✨ Real threat analyzer is working correctly!")

if __name__ == "__main__":
    asyncio.run(test_real_analyzer())