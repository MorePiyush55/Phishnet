"""
OAuth Callback URL Analyzer
Analyzes the actual callback URL from Google OAuth to identify configuration issues
"""

import urllib.parse

def analyze_callback_url():
    """Analyze the OAuth callback URL from Google"""
    
    # The actual callback URL from Google
    callback_url = "https://phishnet-backend-juoc.onrender.com/api/v1/auth/gmail/callback?state=cJUda6khwbumScXGD9P3Ww7nqRgeHsDYjaG6dDSgLxQ&code=4/0AVGzR1DmaWjeoycvWbK7CvNqiw7PCFxtF9Zw0763EMaUkaiVrYV772ImB-VOT_QkojBm8A&scope=email%20profile%20https://www.googleapis.com/auth/gmail.readonly%20https://www.googleapis.com/auth/userinfo.profile%20https://www.googleapis.com/auth/userinfo.email%20openid&authuser=1&prompt=consent"
    
    print("🔍 OAuth Callback URL Analysis")
    print("=" * 60)
    
    # Parse the URL
    parsed_url = urllib.parse.urlparse(callback_url)
    query_params = urllib.parse.parse_qs(parsed_url.query)
    
    print(f"🌐 Server: {parsed_url.netloc}")
    print(f"📍 Path: {parsed_url.path}")
    print(f"📝 State: {query_params.get('state', [''])[0][:20]}...")
    print(f"🔑 Code: {query_params.get('code', [''])[0][:20]}...")
    print(f"🔐 Scopes: {', '.join(urllib.parse.unquote(s) for s in query_params.get('scope', ['']))}")
    
    print("\n" + "=" * 60)
    print("❌ PROBLEM IDENTIFIED:")
    print(f"   Google is redirecting to: {parsed_url.netloc}")
    print(f"   But your backend is at: phishnet-backend-iuoc.onrender.com")
    print("\n💡 SOLUTIONS:")
    print("   1. Update Google OAuth Console redirect URI")
    print("   2. Or redirect traffic from old URL to new URL")
    print("   3. Or update backend environment variables")
    
    # Check if this is the correct callback URL for the working backend
    correct_url = callback_url.replace("phishnet-backend-juoc", "phishnet-backend-iuoc")
    print(f"\n✅ CORRECTED URL:")
    print(f"   {correct_url}")
    
    return correct_url

def test_corrected_callback():
    """Test the corrected callback URL"""
    import requests
    
    corrected_url = analyze_callback_url()
    
    print("\n🧪 Testing Corrected URL...")
    print("-" * 40)
    
    try:
        # Extract just the base endpoint without parameters
        base_url = corrected_url.split('?')[0]
        response = requests.get(base_url, timeout=10)
        print(f"✅ Corrected endpoint status: {response.status_code}")
        
        if response.status_code == 400:
            print("   (400 is expected - endpoint exists but needs OAuth parameters)")
        elif response.status_code == 404:
            print("   ❌ Still not found - router may not be loaded")
        else:
            print(f"   Response: {response.text[:100]}...")
            
    except Exception as e:
        print(f"❌ Error testing corrected URL: {e}")

if __name__ == "__main__":
    test_corrected_callback()