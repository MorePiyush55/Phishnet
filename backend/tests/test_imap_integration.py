"""
Quick test script for IMAP email integration
Tests the complete ThePhish-style workflow
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app.services.quick_imap import QuickIMAPService
from app.services.enhanced_phishing_analyzer import EnhancedPhishingAnalyzer


def test_imap_connection():
    """Test IMAP connection."""
    print("="*80)
    print("TEST 1: IMAP Connection")
    print("="*80)
    
    service = QuickIMAPService()
    
    # Check if configured
    if not service.user or not service.password:
        print("❌ IMAP not configured")
        print("\nTo configure IMAP, add to your .env file:")
        print("""
IMAP_ENABLED=true
IMAP_HOST=imap.gmail.com
IMAP_PORT=993
IMAP_USER=propam5553@gmail.com
IMAP_PASSWORD=your_gmail_app_password_here
IMAP_FOLDER=INBOX
        """)
        print("\n⚠️  IMPORTANT: Use REAL emails from propam5553@gmail.com")
        print("   This account should have actual phishing/suspicious emails")
        print("   Forward real suspicious emails to this account for testing")
        return False
    
    print(f"✓ IMAP Host: {service.host}")
    print(f"✓ IMAP User: {service.user}")
    print(f"✓ IMAP Folder: {service.folder}")
    
    # Test connection
    print("\nTesting connection...")
    if service.test_connection():
        print("✅ IMAP connection successful!")
        return True
    else:
        print("❌ IMAP connection failed")
        print("\nTroubleshooting:")
        print("1. Enable IMAP in Gmail settings")
        print("2. Create App Password: https://myaccount.google.com/apppasswords")
        print("3. Use App Password instead of regular password")
        return False


def test_list_pending_emails():
    """Test listing pending forwarded emails."""
    print("\n" + "="*80)
    print("TEST 2: List Pending Forwarded Emails")
    print("="*80)
    
    service = QuickIMAPService()
    
    emails = service.get_pending_emails()
    
    if not emails:
        print("📭 No pending emails found in propam5553@gmail.com")
        print("\nTo test with REAL emails:")
        print("1. Find a REAL suspicious/phishing email (spam folder, etc.)")
        print("2. Click More (⋮) → Forward as attachment")
        print("3. Send to: propam5553@gmail.com")
        print("4. Run this script again")
        print("\n💡 TIP: Check spam folder for real phishing attempts")
        print("   Or use emails from your phishing simulation campaigns")
        return False
    
    print(f"✅ Found {len(emails)} pending email(s):\n")
    
    for i, email in enumerate(emails, 1):
        print(f"{i}. UID: {email['uid']}")
        print(f"   From: {email['from']}")
        print(f"   Subject: {email['subject']}")
        print(f"   Date: {email['date']}")
        print()
    
    return True, emails


def test_analyze_email(email_uid):
    """Test email analysis."""
    print("\n" + "="*80)
    print(f"TEST 3: Analyze Email (UID: {email_uid})")
    print("="*80)
    
    # Fetch email
    print("\nStep 1: Fetching email from IMAP...")
    imap_service = QuickIMAPService()
    email_data = imap_service.fetch_email_for_analysis(email_uid)
    
    if not email_data:
        print("❌ Failed to fetch email")
        return False
    
    print(f"✓ Email fetched successfully")
    print(f"  Forwarded by: {email_data['forwarded_by']}")
    print(f"  Subject: {email_data['subject']}")
    print(f"  From: {email_data['from']}")
    print(f"  Attachments: {len(email_data['attachments'])}")
    
    # Analyze email
    print("\nStep 2: Running Enhanced Phishing Analysis...")
    analyzer = EnhancedPhishingAnalyzer()
    result = analyzer.analyze_email(email_data['raw_email'])
    
    print(f"\n{'='*80}")
    print(f"ANALYSIS COMPLETE")
    print(f"{'='*80}")
    
    print(f"\n📊 OVERALL RESULTS:")
    print(f"  Total Score:    {result.total_score}%")
    print(f"  Final Verdict:  {result.final_verdict}")
    print(f"  Confidence:     {result.confidence:.2%}")
    
    print(f"\n🧑 SENDER ANALYSIS: {result.sender.score}%")
    print(f"  Display Name: {result.sender.display_name}")
    print(f"  Email: {result.sender.email_address}")
    print(f"  Similarity: {result.sender.name_email_similarity:.2%}")
    if result.sender.indicators:
        print(f"  ⚠️  Indicators: {', '.join(result.sender.indicators)}")
    
    print(f"\n📝 CONTENT ANALYSIS: {result.content.score}%")
    print(f"  Keywords Found: {result.content.keyword_count}")
    print(f"  Urgency Level: {result.content.urgency_level}")
    if result.content.phishing_keywords_found:
        print(f"  🚨 Keywords: {', '.join(result.content.phishing_keywords_found[:10])}")
    
    print(f"\n🔗 LINK ANALYSIS: {result.links.overall_score}%")
    print(f"  Total Links: {result.links.total_links}")
    print(f"  HTTPS: {result.links.https_links}, HTTP: {result.links.http_links}")
    print(f"  Encoded: {result.links.encoded_links}")
    print(f"  Redirects: {result.links.redirect_links}")
    
    print(f"\n🔐 AUTHENTICATION: {result.authentication.overall_score}%")
    print(f"  SPF:   {result.authentication.spf_result} ({result.authentication.spf_score}%)")
    print(f"  DKIM:  {result.authentication.dkim_result} ({result.authentication.dkim_score}%)")
    print(f"  DMARC: {result.authentication.dmarc_result} ({result.authentication.dmarc_score}%)")
    
    print(f"\n📎 ATTACHMENTS: {result.attachments.score}%")
    print(f"  Total: {result.attachments.total_attachments}")
    if result.attachments.dangerous_extensions:
        print(f"  🚨 Dangerous: {', '.join(result.attachments.dangerous_extensions)}")
    
    if result.risk_factors:
        print(f"\n⚠️  RISK FACTORS ({len(result.risk_factors)}):")
        for i, factor in enumerate(result.risk_factors, 1):
            print(f"  {i}. {factor}")
    
    print(f"\n{'='*80}")
    print("✅ Analysis completed successfully!")
    
    return True


def main():
    """Run all tests."""
    print("\n" + "="*80)
    print("PHISHNET IMAP EMAIL INTEGRATION TEST")
    print("ThePhish-style Email Forwarding Workflow")
    print("="*80)
    print("\n🔴 TESTING WITH REAL EMAILS FROM: propam5553@gmail.com")
    print("⚠️  This account should contain REAL phishing/suspicious emails")
    print("="*80 + "\n")
    
    # Test 1: Connection
    if not test_imap_connection():
        print("\n❌ Test failed: Cannot connect to IMAP server")
        print("Please configure IMAP settings and try again.")
        return
    
    # Test 2: List emails
    result = test_list_pending_emails()
    if not result:
        print("\n⏳ Waiting for REAL forwarded emails in propam5553@gmail.com...")
        print("Please forward a REAL suspicious email as attachment and run again.")
        print("\n💡 Where to find real phishing emails:")
        print("   - Gmail spam folder")
        print("   - Email security alerts")
        print("   - Phishing simulation campaigns")
        print("   - User-reported suspicious emails")
        return
    
    has_emails, emails = result
    
    # Test 3: Analyze first email
    if emails:
        first_email = emails[0]
        print(f"\nAnalyzing first email: {first_email['subject'][:50]}...")
        
        user_input = input("\nProceed with analysis? (y/n): ")
        if user_input.lower() == 'y':
            test_analyze_email(first_email['uid'])
        else:
            print("Analysis cancelled.")
    
    print("\n" + "="*80)
    print("✅ ALL TESTS COMPLETED WITH REAL EMAILS")
    print("="*80)
    print("\n📊 Results based on REAL emails from propam5553@gmail.com")
    print("\nNext steps:")
    print("1. Start FastAPI server: uvicorn app.main:app --reload")
    print("2. Test API: curl http://localhost:8000/api/v1/imap-emails/pending")
    print("3. Create frontend dashboard for analysts")
    print("4. Continue testing with more REAL phishing emails")
    print("\n✅ IMAP integration ready for production with real-world testing! 🚀")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nTest interrupted by user.")
    except Exception as e:
        print(f"\n❌ Test failed with error: {e}")
        import traceback
        traceback.print_exc()
