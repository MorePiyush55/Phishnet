"""
Quick OAuth Callback Fix for PhishNet Production Deployment
This script checks and creates the missing OAuth callback endpoint
"""

import requests
import sys

BACKEND_URL = "https://phishnet-backend-iuoc.onrender.com"

def test_current_endpoints():
    """Test current endpoint availability"""
    endpoints_to_test = [
        "/api/v1/auth/gmail/callback",
        "/api/v1/oauth/callback", 
        "/api/rest/auth/callback",
        "/callback",
        "/oauth/callback"
    ]
    
    print("🔍 Testing OAuth callback endpoints...")
    print("-" * 50)
    
    for endpoint in endpoints_to_test:
        try:
            response = requests.get(f"{BACKEND_URL}{endpoint}", timeout=10, allow_redirects=False)
            status = response.status_code
            if status == 404:
                print(f"❌ {endpoint} - Not Found (404)")
            elif status in [200, 302, 307, 400, 422]:
                print(f"✅ {endpoint} - Available ({status})")
            else:
                print(f"⚠️  {endpoint} - Status {status}")
        except Exception as e:
            print(f"❌ {endpoint} - Error: {e}")
    
    print("\n" + "=" * 50)

def check_oauth_configuration():
    """Check OAuth configuration"""
    print("🔧 Checking OAuth Configuration...")
    print("-" * 50)
    
    # Test OAuth initiation
    try:
        response = requests.get(f"{BACKEND_URL}/api/rest/auth/google", timeout=10, allow_redirects=False)
        if response.status_code in [302, 307]:
            location = response.headers.get('Location', '')
            print(f"✅ OAuth initiation working: {location[:80]}...")
            
            # Extract redirect_uri from the OAuth URL
            if 'redirect_uri=' in location:
                import urllib.parse
                parsed = urllib.parse.parse_qs(urllib.parse.urlparse(location).query)
                redirect_uri = parsed.get('redirect_uri', [''])[0]
                if redirect_uri:
                    redirect_uri = urllib.parse.unquote(redirect_uri)
                    print(f"📍 Google OAuth redirect URI: {redirect_uri}")
                    return redirect_uri
        else:
            print(f"❌ OAuth initiation failed: HTTP {response.status_code}")
    except Exception as e:
        print(f"❌ OAuth initiation error: {e}")
    
    return None

def main():
    print("🚀 PhishNet OAuth Callback Diagnosis")
    print("=" * 60)
    
    # Test endpoints
    test_current_endpoints()
    
    # Check OAuth configuration
    redirect_uri = check_oauth_configuration()
    
    print("\n📋 DIAGNOSIS SUMMARY:")
    print("-" * 30)
    
    if redirect_uri:
        if "phishnet-backend-iuoc.onrender.com" in redirect_uri:
            print("✅ OAuth redirect URI correctly points to production backend")
            if "/api/v1/auth/gmail/callback" in redirect_uri:
                print("✅ Redirect URI format is correct")
                print("\n💡 SOLUTION: The Gmail OAuth router may not be loading properly.")
                print("   Check backend logs for 'Gmail OAuth router loaded successfully'")
            else:
                print(f"⚠️  Unexpected redirect URI format: {redirect_uri}")
        else:
            print(f"❌ OAuth redirect URI points to wrong server: {redirect_uri}")
            print("💡 SOLUTION: Update Google OAuth console redirect URI to:")
            print(f"   https://phishnet-backend-iuoc.onrender.com/api/v1/auth/gmail/callback")
    else:
        print("❌ Could not determine OAuth redirect URI")
    
    print("\n🔧 IMMEDIATE ACTIONS:")
    print("1. Check Google OAuth Console redirect URI settings")
    print("2. Verify backend environment variables for GMAIL_REDIRECT_URI") 
    print("3. Check backend logs for router loading issues")
    print("4. Test the callback endpoint directly")

if __name__ == "__main__":
    main()