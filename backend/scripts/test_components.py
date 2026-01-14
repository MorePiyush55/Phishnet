"""
PhishNet Component Test Suite
Tests all analysis modules and provides working scores.
"""

import asyncio
import sys
import os

# Load environment variables from .env file first
from dotenv import load_dotenv
backend_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
env_path = os.path.join(backend_dir, '.env')
load_dotenv(env_path)
print(f"Loaded .env from: {env_path}")

# Add backend to path
sys.path.insert(0, backend_dir)

from datetime import datetime


async def test_all_components():
    """Test all PhishNet analysis components and report scores."""
    
    print("=" * 60)
    print("       PhishNet Component Test Suite")
    print("=" * 60)
    print(f"Started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
    
    results = {}
    
    # ========================================
    # 1. Test EnhancedPhishingAnalyzer
    # ========================================
    print("🔍 Testing EnhancedPhishingAnalyzer...")
    try:
        from app.services.enhanced_phishing_analyzer import EnhancedPhishingAnalyzer
        
        analyzer = EnhancedPhishingAnalyzer()
        
        # Create test email
        test_email = b"""From: "Security Team" <security@example-bank.com>
To: victim@gmail.com
Subject: URGENT: Your account will be suspended
Date: Mon, 14 Jan 2026 10:00:00 +0000
MIME-Version: 1.0
Content-Type: text/html; charset=utf-8

<html>
<body>
<p>Dear Customer,</p>
<p>Your account has been compromised. Click here immediately to verify:</p>
<a href="http://bit.ly/fake-bank-login">Verify Now</a>
<p>If you don't act within 24 hours, your account will be suspended!</p>
<p>Best regards,<br>Security Team</p>
</body>
</html>
"""
        
        result = analyzer.analyze_email(test_email)
        
        print(f"  ✅ Sender Analysis:     {result.sender.score}/100")
        print(f"  ✅ Content Analysis:    {result.content.score}/100")
        print(f"  ✅ Link Analysis:       {result.links.overall_score}/100")
        print(f"  ✅ Auth Analysis:       {result.authentication.overall_score}/100")
        print(f"  ✅ Attachment Analysis: {result.attachments.score}/100")
        print(f"  ✅ Final Verdict:       {result.final_verdict}")
        print(f"  ✅ Total Score:         {result.total_score}/100")
        
        results['EnhancedPhishingAnalyzer'] = {
            'status': 'WORKING',
            'score': 100,
            'details': f"Verdict: {result.final_verdict}, Score: {result.total_score}"
        }
    except Exception as e:
        print(f"  ❌ Error: {e}")
        results['EnhancedPhishingAnalyzer'] = {'status': 'FAILED', 'score': 0, 'error': str(e)}
    
    print()
    
    # ========================================
    # 2. Test Gemini AI Client
    # ========================================
    print("🤖 Testing Gemini AI Client...")
    try:
        from app.services.gemini import GeminiClient
        
        gemini = GeminiClient()
        
        if gemini.api_key:
            # Test with simple text
            health = await gemini.health_check()
            
            if health.status.value == 'healthy':
                results['GeminiClient'] = {
                    'status': 'WORKING',
                    'score': 100,
                    'details': "API connected and responding"
                }
                print(f"  ✅ API Key: Configured")
                print(f"  ✅ Health: {health.status.value}")
            else:
                results['GeminiClient'] = {
                    'status': 'DEGRADED',
                    'score': 50,
                    'details': f"Status: {health.status.value}"
                }
                print(f"  ⚠️ Health: {health.status.value}")
        else:
            print(f"  ⚠️ API Key: Not configured")
            results['GeminiClient'] = {
                'status': 'NOT_CONFIGURED',
                'score': 0,
                'details': "No API key found"
            }
    except Exception as e:
        print(f"  ❌ Error: {e}")
        results['GeminiClient'] = {'status': 'FAILED', 'score': 0, 'error': str(e)}
    
    print()
    
    # ========================================
    # 3. Test VirusTotal Client
    # ========================================
    print("🛡️ Testing VirusTotal Client...")
    try:
        from app.services.virustotal import VirusTotalClient
        
        vt = VirusTotalClient()
        
        if vt.api_key:
            print(f"  ✅ API Key: Configured")
            
            # Test URL scan
            try:
                test_result = await vt.scan("https://google.com")
                print(f"  ✅ URL Scan: Working (verdict: {test_result.get('verdict', 'N/A')})")
                results['VirusTotalClient'] = {
                    'status': 'WORKING',
                    'score': 100,
                    'details': "API connected, URL scan successful"
                }
            except Exception as scan_err:
                print(f"  ⚠️ URL Scan: {scan_err}")
                results['VirusTotalClient'] = {
                    'status': 'DEGRADED',
                    'score': 50,
                    'details': f"API key configured but scan failed: {scan_err}"
                }
        else:
            print(f"  ⚠️ API Key: Not configured")
            results['VirusTotalClient'] = {
                'status': 'NOT_CONFIGURED',
                'score': 0,
                'details': "No API key - set VIRUSTOTAL_API_KEY"
            }
    except Exception as e:
        print(f"  ❌ Error: {e}")
        results['VirusTotalClient'] = {'status': 'FAILED', 'score': 0, 'error': str(e)}
    
    print()
    
    # ========================================
    # 4. Test AbuseIPDB Client
    # ========================================
    print("🌐 Testing AbuseIPDB Client...")
    try:
        from app.services.abuseipdb import AbuseIPDBClient
        
        abuseipdb = AbuseIPDBClient()
        
        if abuseipdb.api_key:
            print(f"  ✅ API Key: Configured")
            
            try:
                # Test with Google's DNS
                health = await abuseipdb.health_check()
                print(f"  ✅ Health: {health.status.value}")
                results['AbuseIPDBClient'] = {
                    'status': 'WORKING',
                    'score': 100,
                    'details': "API connected and healthy"
                }
            except Exception as check_err:
                print(f"  ⚠️ Check: {check_err}")
                results['AbuseIPDBClient'] = {
                    'status': 'DEGRADED',
                    'score': 50,
                    'details': str(check_err)
                }
        else:
            print(f"  ⚠️ API Key: Not configured")
            results['AbuseIPDBClient'] = {
                'status': 'NOT_CONFIGURED',
                'score': 0,
                'details': "No API key - set ABUSEIPDB_API_KEY"
            }
    except Exception as e:
        print(f"  ❌ Error: {e}")
        results['AbuseIPDBClient'] = {'status': 'FAILED', 'score': 0, 'error': str(e)}
    
    print()
    
    # ========================================
    # 5. Test IMAP Service
    # ========================================
    print("📬 Testing IMAP Service...")
    try:
        from app.services.quick_imap import QuickIMAPService
        
        imap = QuickIMAPService()
        
        # Test connection
        try:
            recent = await imap.get_recent_emails(limit=1)
            print(f"  ✅ Connection: Working")
            print(f"  ✅ Recent Emails: {len(recent)} fetched")
            results['QuickIMAPService'] = {
                'status': 'WORKING',
                'score': 100,
                'details': f"Connected, {len(recent)} emails available"
            }
        except Exception as conn_err:
            print(f"  ⚠️ Connection: {conn_err}")
            results['QuickIMAPService'] = {
                'status': 'FAILED',
                'score': 0,
                'details': str(conn_err)
            }
    except Exception as e:
        print(f"  ❌ Error: {e}")
        results['QuickIMAPService'] = {'status': 'FAILED', 'score': 0, 'error': str(e)}
    
    print()
    
    # ========================================
    # 6. Test Email Sender
    # ========================================
    print("📧 Testing Email Sender...")
    try:
        from app.services.email_sender import EmailSender
        
        sender = EmailSender()
        
        if sender.api_key or getattr(sender, 'smtp_configured', False):
            print(f"  ✅ Configuration: Valid")
            results['EmailSender'] = {
                'status': 'WORKING',
                'score': 100,
                'details': "Email sending configured"
            }
        else:
            print(f"  ⚠️ Configuration: Not fully configured")
            results['EmailSender'] = {
                'status': 'NOT_CONFIGURED',
                'score': 50,
                'details': "Check SMTP/API settings"
            }
    except Exception as e:
        print(f"  ❌ Error: {e}")
        results['EmailSender'] = {'status': 'FAILED', 'score': 0, 'error': str(e)}
    
    print()
    
    # ========================================
    # Summary Report
    # ========================================
    print("=" * 60)
    print("                   SUMMARY REPORT")
    print("=" * 60)
    print()
    print(f"{'Component':<30} {'Status':<15} {'Score':<10}")
    print("-" * 60)
    
    total_score = 0
    count = 0
    
    for component, result in results.items():
        status = result['status']
        score = result['score']
        total_score += score
        count += 1
        
        status_emoji = {
            'WORKING': '✅',
            'DEGRADED': '⚠️',
            'NOT_CONFIGURED': '⛔',
            'FAILED': '❌'
        }.get(status, '❓')
        
        print(f"{component:<30} {status_emoji} {status:<12} {score}/100")
    
    print("-" * 60)
    avg_score = total_score / count if count > 0 else 0
    print(f"{'OVERALL SCORE':<30} {'':15} {avg_score:.0f}/100")
    print()
    
    # Recommendations
    print("📋 RECOMMENDATIONS:")
    for component, result in results.items():
        if result['status'] == 'NOT_CONFIGURED':
            print(f"  • Configure {component}: {result.get('details', '')}")
        elif result['status'] == 'FAILED':
            print(f"  • Fix {component}: {result.get('error', result.get('details', ''))}")
    
    print()
    print(f"Completed at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    return results


if __name__ == "__main__":
    asyncio.run(test_all_components())
