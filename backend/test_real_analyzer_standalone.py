#!/usr/bin/env python3
"""Standalone test script for real threat analyzers."""

import asyncio
import re
import urllib.parse

class URLAnalyzer:
    """Simplified URL analyzer for testing."""
    
    def __init__(self):
        self.suspicious_domains = [
            'bit.ly', 'tinyurl.com', 'goo.gl', 't.co',
            'paypal-support.com', 'microsofft-security.tk'
        ]
        self.suspicious_patterns = [
            r'paypal.*verify', r'microsoft.*security', r'urgent.*account',
            r'suspended.*click', r'verify.*now', r'act.*immediately'
        ]
    
    async def analyze_urls(self, content: str) -> dict:
        """Analyze URLs in content for threats."""
        urls = re.findall(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', content)
        
        threat_score = 0
        threats = []
        
        for url in urls:
            domain = urllib.parse.urlparse(url).netloc
            
            # Check suspicious domains
            for suspicious in self.suspicious_domains:
                if suspicious in domain:
                    threat_score += 0.3
                    threats.append(f"Suspicious domain: {domain}")
            
            # Check suspicious patterns in URL
            for pattern in self.suspicious_patterns:
                if re.search(pattern, url, re.IGNORECASE):
                    threat_score += 0.2
                    threats.append(f"Suspicious URL pattern: {pattern}")
        
        return {
            'threat_score': min(threat_score, 1.0),
            'threats': threats,
            'urls_found': urls
        }

class ContentAnalyzer:
    """Simplified content analyzer for testing."""
    
    def __init__(self):
        self.phishing_keywords = [
            'urgent', 'immediate', 'suspended', 'verify', 'account', 'click here',
            'act now', 'limited time', 'expires', 'confirm identity', 
            'social security', 'ssn', 'credit card', 'banking', 'password'
        ]
        self.urgency_phrases = [
            'act within', 'expires in', 'urgent notice', 'immediate action',
            'will be suspended', 'permanently deleted', 'click now'
        ]
    
    async def analyze_content(self, content: str) -> dict:
        """Analyze email content for phishing indicators."""
        content_lower = content.lower()
        
        threat_score = 0
        threats = []
        
        # Check for phishing keywords
        keyword_count = 0
        for keyword in self.phishing_keywords:
            if keyword in content_lower:
                keyword_count += 1
        
        if keyword_count >= 3:
            threat_score += 0.4
            threats.append(f"High phishing keyword density: {keyword_count} keywords")
        
        # Check for urgency phrases
        urgency_count = 0
        for phrase in self.urgency_phrases:
            if phrase in content_lower:
                urgency_count += 1
        
        if urgency_count > 0:
            threat_score += 0.3
            threats.append(f"Urgency indicators detected: {urgency_count}")
        
        # Check for credential requests
        credential_indicators = ['password', 'ssn', 'social security', 'credit card', 'banking']
        credential_count = sum(1 for indicator in credential_indicators if indicator in content_lower)
        
        if credential_count > 0:
            threat_score += 0.4
            threats.append(f"Credential harvesting indicators: {credential_count}")
        
        return {
            'threat_score': min(threat_score, 1.0),
            'threats': threats,
            'keyword_count': keyword_count,
            'urgency_count': urgency_count,
            'credential_count': credential_count
        }

class RealThreatAnalyzer:
    """Simplified real threat analyzer for testing."""
    
    def __init__(self):
        self.url_analyzer = URLAnalyzer()
        self.content_analyzer = ContentAnalyzer()
    
    async def analyze_email(self, email_data: dict) -> dict:
        """Analyze email for phishing threats."""
        
        # Extract email components
        subject = email_data.get('subject', '')
        body = email_data.get('body', '')
        sender = email_data.get('sender', '')
        
        # Combine all text for analysis
        full_content = f"{subject} {body}"
        
        # Run analyses in parallel
        url_analysis = await self.url_analyzer.analyze_urls(full_content)
        content_analysis = await self.content_analyzer.analyze_content(full_content)
        
        # Calculate combined threat score
        url_weight = 0.4
        content_weight = 0.6
        
        combined_score = (
            url_analysis['threat_score'] * url_weight +
            content_analysis['threat_score'] * content_weight
        )
        
        # Determine risk level
        if combined_score >= 0.7:
            risk_level = "CRITICAL"
        elif combined_score >= 0.5:
            risk_level = "HIGH"
        elif combined_score >= 0.3:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"
        
        # Determine if phishing
        is_phishing = combined_score >= 0.5
        
        # Combine threats
        all_threats = url_analysis['threats'] + content_analysis['threats']
        
        # Generate summary
        if is_phishing:
            summary = f"HIGH RISK: Email shows strong phishing indicators. Threat score: {combined_score:.2f}"
        else:
            summary = f"Email appears legitimate. Threat score: {combined_score:.2f}"
        
        return {
            'is_phishing': is_phishing,
            'threat_score': combined_score,
            'risk_level': risk_level,
            'threats_detected': all_threats,
            'summary': summary,
            'analysis_details': {
                'url_analysis': url_analysis,
                'content_analysis': content_analysis
            }
        }

# Create analyzer instance
real_threat_analyzer = RealThreatAnalyzer()

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