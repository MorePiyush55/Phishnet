#!/usr/bin/env python3
"""
Test the CORRECT Render URL from the logs
"""

import requests

# The CORRECT URL from Render logs
BASE_URL = "https://phishnet-backend-iuoc.onrender.com"

def test_correct_url():
    print(f"🔍 Testing CORRECT Render URL: {BASE_URL}")
    print("=" * 60)
    
    endpoints = [
        "/",
        "/health", 
        "/docs",
        "/api/rest/auth/google",
        "/api/test/oauth"
    ]
    
    for endpoint in endpoints:
        url = f"{BASE_URL}{endpoint}"
        try:
            print(f"\n🧪 Testing: {endpoint}")
            print(f"📡 URL: {url}")
            
            response = requests.get(url, timeout=10)
            print(f"📊 Status Code: {response.status_code}")
            print(f"📋 Headers: {dict(response.headers)}")
            
            # Check for Render routing issues
            routing_header = response.headers.get('x-render-routing', 'ok')
            if routing_header != 'ok':
                print(f"🚦 Render Routing: {routing_header}")
                if routing_header == 'no-server':
                    print("❌ ISSUE: Render service is not running!")
            else:
                print("✅ Render routing OK!")
                
            print(f"📄 Response: {response.text[:200]}...")
            
        except requests.exceptions.RequestException as e:
            print(f"❌ Error: {e}")

if __name__ == "__main__":
    test_correct_url()