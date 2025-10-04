"""
OAuth Configuration Fixer
Fix the OAuth redirect URI configuration in the backend
"""

def check_backend_configuration():
    """Check what redirect URIs are configured in the backend"""
    import requests
    
    print("🔧 Backend OAuth Configuration Analysis")
    print("=" * 50)
    
    # Check the OAuth initiation to see what redirect_uri is being sent to Google
    try:
        response = requests.get(
            "https://phishnet-backend-iuoc.onrender.com/api/rest/auth/google", 
            allow_redirects=False,
            timeout=10
        )
        
        if response.status_code in [302, 307]:
            location = response.headers.get('Location', '')
            print(f"✅ OAuth redirect URL: {location[:100]}...")
            
            # Extract the redirect_uri parameter
            import urllib.parse
            parsed = urllib.parse.parse_qs(urllib.parse.urlparse(location).query)
            redirect_uri = parsed.get('redirect_uri', [''])[0]
            
            if redirect_uri:
                redirect_uri = urllib.parse.unquote(redirect_uri)
                print(f"\n📍 Backend redirect_uri setting: {redirect_uri}")
                
                if "phishnet-backend-juoc" in redirect_uri:
                    print("❌ PROBLEM: Backend is configured with OLD server URL (juoc)")
                    print("💡 SOLUTION: Update backend environment variable GMAIL_REDIRECT_URI")
                    print(f"   Current: {redirect_uri}")
                    print(f"   Should be: {redirect_uri.replace('juoc', 'iuoc')}")
                elif "phishnet-backend-iuoc" in redirect_uri:
                    print("✅ Backend redirect_uri is correct")
                else:
                    print(f"⚠️  Unexpected redirect_uri: {redirect_uri}")
                    
                return redirect_uri
        else:
            print(f"❌ OAuth initiation failed: {response.status_code}")
            
    except Exception as e:
        print(f"❌ Error checking backend config: {e}")
        
    return None

def test_gmail_callback_redirect():
    """Test what happens when accessing the Gmail callback"""
    import requests
    
    print("\n🧪 Testing Gmail Callback Redirect")
    print("-" * 40)
    
    try:
        response = requests.get(
            "https://phishnet-backend-iuoc.onrender.com/api/v1/auth/gmail/callback",
            allow_redirects=False,
            timeout=10
        )
        
        print(f"Status: {response.status_code}")
        if response.status_code in [302, 307]:
            location = response.headers.get('Location', '')
            print(f"Redirects to: {location}")
            
            if "phishnet-backend-juoc" in location:
                print("❌ PROBLEM: Gmail callback redirects to OLD server (juoc)")
            elif "phishnet-backend-iuoc" in location:
                print("✅ Gmail callback redirects to correct server")
            else:
                print(f"⚠️  Unexpected redirect: {location}")
        else:
            print(f"Response: {response.text[:200]}")
            
    except Exception as e:
        print(f"❌ Error testing callback: {e}")

def main():
    print("🚀 OAuth Configuration Fix Analysis")
    print("=" * 60)
    
    # Check backend configuration
    redirect_uri = check_backend_configuration()
    
    # Test callback redirect
    test_gmail_callback_redirect()
    
    print("\n" + "=" * 60)
    print("📋 SUMMARY & SOLUTION:")
    print("=" * 60)
    
    if redirect_uri and "phishnet-backend-juoc" in redirect_uri:
        print("❌ ROOT CAUSE: Backend environment variable GMAIL_REDIRECT_URI")
        print("   is set to the old server URL (juoc)")
        print("\n🔧 SOLUTION:")
        print("   1. Update Render environment variable:")
        print("      GMAIL_REDIRECT_URI=https://phishnet-backend-iuoc.onrender.com/api/v1/auth/gmail/callback")
        print("   2. Restart the backend service")
        print("   3. Test OAuth flow again")
    else:
        print("✅ Backend configuration appears correct")
        print("   Check Google OAuth Console redirect URIs")

if __name__ == "__main__":
    main()