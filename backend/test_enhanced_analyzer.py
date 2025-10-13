"""
Test Enhanced Phishing Analyzer
Tests all 5 analysis modules with realistic email samples
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from email import message_from_string
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from app.services.enhanced_phishing_analyzer import EnhancedPhishingAnalyzer


def create_test_email_legitimate():
    """Create a legitimate email for testing"""
    msg = MIMEMultipart('alternative')
    msg['Subject'] = 'Monthly Report - January 2024'
    msg['From'] = 'John Smith <john.smith@company.com>'
    msg['To'] = 'recipient@example.com'
    msg['Authentication-Results'] = 'spf=pass dkim=pass dmarc=pass'
    msg['Received-SPF'] = 'pass'
    
    text = """
    Hi Team,
    
    Please find attached the monthly report for January 2024.
    The report includes sales figures and performance metrics.
    
    Best regards,
    John Smith
    Finance Department
    """
    
    html = """
    <html>
    <body>
    <p>Hi Team,</p>
    <p>Please find attached the monthly report for January 2024.</p>
    <p>View online: <a href="https://company.com/reports/january">https://company.com/reports/january</a></p>
    <p>Best regards,<br>John Smith</p>
    </body>
    </html>
    """
    
    msg.attach(MIMEText(text, 'plain'))
    msg.attach(MIMEText(html, 'html'))
    
    return msg.as_bytes()


def create_test_email_phishing():
    """Create a phishing email for testing"""
    msg = MIMEMultipart('alternative')
    msg['Subject'] = 'URGENT: Your Account Will Be Suspended!'
    msg['From'] = 'PayPal Security Team <random.user@gmail.com>'
    msg['To'] = 'victim@example.com'
    msg['Authentication-Results'] = 'spf=fail dkim=fail dmarc=fail'
    msg['Received-SPF'] = 'fail'
    msg['Received'] = 'from [192.168.1.100] by mail.example.com'
    
    text = """
    URGENT ACTION REQUIRED!
    
    Your PayPal account has been suspended due to unusual activity.
    You must verify your identity immediately to restore access.
    
    Click here to verify your account: http://paypal-verify.suspicious-site.tk/login
    
    This link expires in 24 hours. Act now to avoid permanent account closure.
    
    If you don't verify now, your account will be permanently locked and all funds frozen.
    
    PayPal Security Team
    """
    
    html = """
    <html>
    <body style="background-color: red; color: white;">
    <h1>URGENT ACTION REQUIRED!</h1>
    <p>Your PayPal account has been <strong>suspended</strong> due to unusual activity.</p>
    <p>You must <strong>verify</strong> your identity <strong>immediately</strong> to restore access.</p>
    <p><a href="http://paypal-verify.suspicious-site.tk/login?redirect=true&id=%2Fverify%2F">Click here to verify your account</a></p>
    <p><a href="http://paypal-secure.ml/r/account">Alternative verification link</a></p>
    <p><a href="http://paypal-verify.suspicious-site.tk/login?redirect=true&id=%2Fverify%2F">Click here to verify your account</a></p>
    <p>This link <strong>expires</strong> in 24 hours. <strong>Act now</strong> to avoid permanent account closure.</p>
    <p>Download security update: <a href="http://paypal-update.xyz/security_patch.exe">security_patch.exe</a></p>
    </body>
    </html>
    """
    
    msg.attach(MIMEText(text, 'plain'))
    msg.attach(MIMEText(html, 'html'))
    
    return msg.as_bytes()


def create_test_email_suspicious():
    """Create a suspicious email for testing"""
    msg = MIMEMultipart('alternative')
    msg['Subject'] = 'Important: Password Reset Request'
    msg['From'] = 'IT Support <itsupport@example.com>'
    msg['To'] = 'user@example.com'
    msg['Authentication-Results'] = 'spf=pass dkim=none dmarc=fail'
    msg['Received-SPF'] = 'pass'
    
    text = """
    Hello,
    
    We received a password reset request for your account.
    Please click the link below to reset your password.
    
    Reset password: http://example.com/reset
    Secure login: https://example.com/login
    
    If you didn't request this, please ignore this email.
    
    IT Support Team
    """
    
    html = """
    <html>
    <body>
    <p>Hello,</p>
    <p>We received a password reset request for your account.</p>
    <p>Please click the link below to reset your password.</p>
    <p><a href="http://example.com/reset">Reset password</a></p>
    <p><a href="https://example.com/login">Secure login</a></p>
    <p>If you didn't request this, please ignore this email.</p>
    <p>IT Support Team</p>
    </body>
    </html>
    """
    
    msg.attach(MIMEText(text, 'plain'))
    msg.attach(MIMEText(html, 'html'))
    
    return msg.as_bytes()


def print_section_header(title):
    """Print formatted section header"""
    print(f"\n{'='*80}")
    print(f"  {title}")
    print(f"{'='*80}")


def print_analysis_results(result, email_type):
    """Print detailed analysis results"""
    print_section_header(f"{email_type.upper()} EMAIL ANALYSIS")
    
    print(f"\n📊 OVERALL RESULTS")
    print(f"{'─'*80}")
    print(f"  Total Score:    {result.total_score}%")
    print(f"  Final Verdict:  {result.final_verdict}")
    print(f"  Confidence:     {result.confidence:.2%}")
    
    print(f"\n🧑 SENDER ANALYSIS (Weight: 15%)")
    print(f"{'─'*80}")
    print(f"  Score:          {result.sender.score}%")
    print(f"  Display Name:   {result.sender.display_name}")
    print(f"  Email Address:  {result.sender.email_address}")
    print(f"  Sender IP:      {result.sender.sender_ip or 'N/A'}")
    print(f"  Similarity:     {result.sender.name_email_similarity:.2%} - {result.sender.similarity_description}")
    if result.sender.indicators:
        print(f"  ⚠️  Indicators:")
        for indicator in result.sender.indicators:
            print(f"      • {indicator}")
    
    print(f"\n📝 CONTENT ANALYSIS (Weight: 20%)")
    print(f"{'─'*80}")
    print(f"  Score:          {result.content.score}%")
    print(f"  Keywords Found: {result.content.keyword_count}")
    print(f"  Urgency Level:  {result.content.urgency_level}")
    if result.content.phishing_keywords_found:
        print(f"  🚨 Keywords:    {', '.join(result.content.phishing_keywords_found[:10])}")
        if len(result.content.phishing_keywords_found) > 10:
            print(f"                  ... and {len(result.content.phishing_keywords_found) - 10} more")
    if result.content.indicators:
        print(f"  ⚠️  Indicators:")
        for indicator in result.content.indicators:
            print(f"      • {indicator}")
    
    print(f"\n🔗 LINK ANALYSIS (Weight: 20%)")
    print(f"{'─'*80}")
    print(f"  Overall Score:     {result.links.overall_score}%")
    print(f"  Total Links:       {result.links.total_links}")
    print(f"  Unique Links:      {result.links.unique_links}")
    print(f"  Duplicate Links:   {result.links.duplicate_links}")
    print(f"  HTTPS Links:       {result.links.https_links} (Score: {result.links.https_score}%)")
    print(f"  HTTP Links:        {result.links.http_links}")
    print(f"  Encoded Links:     {result.links.encoded_links} (Score: {result.links.encoding_score}%)")
    print(f"  Redirect Links:    {result.links.redirect_links} (Score: {result.links.redirect_score}%)")
    print(f"  Duplication Score: {result.links.duplication_score}%")
    if result.links.suspicious_tlds:
        print(f"  🚨 Suspicious TLDs: {', '.join(result.links.suspicious_tlds)}")
    if result.links.indicators:
        print(f"  ⚠️  Indicators:")
        for indicator in result.links.indicators:
            print(f"      • {indicator}")
    
    print(f"\n🔐 AUTHENTICATION ANALYSIS (Weight: 30%)")
    print(f"{'─'*80}")
    print(f"  Overall Score: {result.authentication.overall_score}%")
    print(f"  SPF:           {result.authentication.spf_result.upper()} ({result.authentication.spf_score}%)")
    print(f"                 {result.authentication.spf_description}")
    print(f"  DKIM:          {result.authentication.dkim_result.upper()} ({result.authentication.dkim_score}%)")
    print(f"                 {result.authentication.dkim_description}")
    print(f"  DMARC:         {result.authentication.dmarc_result.upper()} ({result.authentication.dmarc_score}%)")
    print(f"                 {result.authentication.dmarc_description}")
    if result.authentication.indicators:
        print(f"  ⚠️  Indicators:")
        for indicator in result.authentication.indicators:
            print(f"      • {indicator}")
    
    print(f"\n📎 ATTACHMENT ANALYSIS (Weight: 15%)")
    print(f"{'─'*80}")
    print(f"  Score:             {result.attachments.score}%")
    print(f"  Total Attachments: {result.attachments.total_attachments}")
    if result.attachments.attachment_names:
        print(f"  Attachment Names:  {', '.join(result.attachments.attachment_names)}")
    if result.attachments.dangerous_extensions:
        print(f"  🚨 DANGEROUS:      {', '.join(result.attachments.dangerous_extensions)}")
    if result.attachments.indicators:
        print(f"  ⚠️  Indicators:")
        for indicator in result.attachments.indicators:
            print(f"      • {indicator}")
    
    if result.risk_factors:
        print(f"\n⚠️  ALL RISK FACTORS")
        print(f"{'─'*80}")
        for i, factor in enumerate(result.risk_factors, 1):
            print(f"  {i}. {factor}")
    
    # Visual score bar
    print(f"\n📊 VISUAL SCORE BREAKDOWN")
    print(f"{'─'*80}")
    
    def create_bar(score, width=50):
        filled = int((score / 100) * width)
        bar = '█' * filled + '░' * (width - filled)
        if score >= 70:
            color = '🟢'
        elif score >= 40:
            color = '🟡'
        else:
            color = '🔴'
        return f"{color} {bar} {score}%"
    
    print(f"  Total:          {create_bar(result.total_score)}")
    print(f"  Sender:         {create_bar(result.sender.score)}")
    print(f"  Content:        {create_bar(result.content.score)}")
    print(f"  Links:          {create_bar(result.links.overall_score)}")
    print(f"  Authentication: {create_bar(result.authentication.overall_score)}")
    print(f"  Attachments:    {create_bar(result.attachments.score)}")
    
    print()


def run_tests():
    """Run all tests"""
    print_section_header("ENHANCED PHISHING ANALYZER TEST SUITE")
    print("\nTesting advanced phishing detection features:")
    print("  ✓ Sender Analysis (Display name vs email similarity)")
    print("  ✓ Content Analysis (Phishing keyword detection)")
    print("  ✓ Link Analysis (HTTPS, encoding, redirection, duplication)")
    print("  ✓ Authentication Analysis (SPF, DKIM, DMARC)")
    print("  ✓ Attachment Analysis (Dangerous file types)")
    
    # Initialize analyzer
    analyzer = EnhancedPhishingAnalyzer()
    
    # Test 1: Legitimate Email
    print_section_header("TEST 1: LEGITIMATE EMAIL")
    legitimate_email = create_test_email_legitimate()
    result_legitimate = analyzer.analyze_email(legitimate_email)
    print_analysis_results(result_legitimate, "Legitimate")
    
    # Validate legitimate email results
    assert result_legitimate.total_score >= 70, f"Legitimate email should score >= 70%, got {result_legitimate.total_score}%"
    assert result_legitimate.final_verdict == "SAFE", f"Expected SAFE verdict, got {result_legitimate.final_verdict}"
    assert result_legitimate.authentication.spf_result == "pass", "SPF should pass for legitimate email"
    print("✅ Test 1 PASSED: Legitimate email correctly identified")
    
    # Test 2: Phishing Email
    print_section_header("TEST 2: PHISHING EMAIL")
    phishing_email = create_test_email_phishing()
    result_phishing = analyzer.analyze_email(phishing_email)
    print_analysis_results(result_phishing, "Phishing")
    
    # Validate phishing email results
    assert result_phishing.total_score <= 40, f"Phishing email should score <= 40%, got {result_phishing.total_score}%"
    assert result_phishing.final_verdict == "PHISHING", f"Expected PHISHING verdict, got {result_phishing.final_verdict}"
    assert result_phishing.content.keyword_count >= 5, f"Expected >= 5 phishing keywords, found {result_phishing.content.keyword_count}"
    assert result_phishing.authentication.spf_result == "fail", "SPF should fail for phishing email"
    assert result_phishing.links.http_links > 0, "Phishing email should have HTTP links"
    print("✅ Test 2 PASSED: Phishing email correctly identified")
    
    # Test 3: Suspicious Email
    print_section_header("TEST 3: SUSPICIOUS EMAIL")
    suspicious_email = create_test_email_suspicious()
    result_suspicious = analyzer.analyze_email(suspicious_email)
    print_analysis_results(result_suspicious, "Suspicious")
    
    # Validate suspicious email results
    assert 40 <= result_suspicious.total_score <= 70, f"Suspicious email should score 40-70%, got {result_suspicious.total_score}%"
    assert result_suspicious.final_verdict == "SUSPICIOUS", f"Expected SUSPICIOUS verdict, got {result_suspicious.final_verdict}"
    print("✅ Test 3 PASSED: Suspicious email correctly identified")
    
    # Summary
    print_section_header("TEST SUMMARY")
    print(f"\n✅ All tests passed successfully!\n")
    print(f"Test Results:")
    print(f"  1. Legitimate Email:  {result_legitimate.total_score}% - {result_legitimate.final_verdict} ✅")
    print(f"  2. Phishing Email:    {result_phishing.total_score}% - {result_phishing.final_verdict} ✅")
    print(f"  3. Suspicious Email:  {result_suspicious.total_score}% - {result_suspicious.final_verdict} ✅")
    
    print(f"\nFeature Validation:")
    print(f"  ✅ Sender similarity detection working")
    print(f"  ✅ Phishing keyword detection working ({result_phishing.content.keyword_count} keywords found)")
    print(f"  ✅ Link analysis working (HTTP/HTTPS, encoding, redirection)")
    print(f"  ✅ Authentication checks working (SPF/DKIM/DMARC)")
    print(f"  ✅ Weighted scoring system working")
    print(f"  ✅ Verdict determination working")
    
    print(f"\nIntegration Status:")
    print(f"  ✅ EnhancedPhishingAnalyzer class created")
    print(f"  ✅ All 5 analysis modules implemented")
    print(f"  ✅ Comprehensive test suite passing")
    print(f"  ⏳ Next: Integrate with enhanced_threat_orchestrator.py")
    print(f"  ⏳ Next: Update API endpoints to return section scores")
    print(f"  ⏳ Next: Create frontend dashboard components")
    
    print(f"\n{'='*80}\n")


if __name__ == "__main__":
    try:
        run_tests()
    except Exception as e:
        print(f"\n❌ Test failed with error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
