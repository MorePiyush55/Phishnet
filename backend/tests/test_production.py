#!/usr/bin/env python3
"""Test OAuth endpoints directly without server."""

import os
import requests
import time

def test_oauth_endpoints():
    """Test OAuth endpoints on local and production servers."""
    
    # Test endpoints to check
    endpoints_to_test = [
        {
            'name': 'Production Backend Health',
            'url': 'https://phishnet-backend-iuoc.onrender.com/health',
            'expected_status': [200, 404]
        },
        {
            'name': 'Production Backend Root',
            'url': 'https://phishnet-backend-iuoc.onrender.com/',
            'expected_status': [200, 404, 405]
        },
        {
            'name': 'Production OAuth REST',
            'url': 'https://phishnet-backend-iuoc.onrender.com/api/rest/auth/google',
            'expected_status': [200, 302, 404, 500]
        },
        {
            'name': 'Production OAuth Test',
            'url': 'https://phishnet-backend-iuoc.onrender.com/api/test/oauth',
            'expected_status': [200, 302, 404, 500]
        },
        {
            'name': 'Production API Docs',
            'url': 'https://phishnet-backend-iuoc.onrender.com/docs',
            'expected_status': [200, 404]
        }
    ]
    
    print("🔍 Testing Production Endpoints on Render...")
    print("=" * 60)
    
    for endpoint in endpoints_to_test:
        try:
            print(f"\n🧪 Testing: {endpoint['name']}")
            print(f"📡 URL: {endpoint['url']}")
            
            response = requests.get(endpoint['url'], timeout=15, allow_redirects=False)
            
            print(f"📊 Status Code: {response.status_code}")
            print(f"📋 Headers: {dict(list(response.headers.items())[:3])}")  # First 3 headers
            
            # Check if status is expected
            if response.status_code in endpoint['expected_status']:
                print(f"✅ Status OK ({response.status_code})")
            else:
                print(f"❌ Unexpected status ({response.status_code})")
            
            # Check response content
            content = response.text[:200] if response.text else "No content"
            print(f"📄 Response: {content}")
            
            # Special checks
            if 'x-render-routing' in response.headers:
                routing_status = response.headers['x-render-routing']
                print(f"🚦 Render Routing: {routing_status}")
                if routing_status == 'no-server':
                    print("❌ ISSUE: Render service is not running!")
            
        except requests.exceptions.Timeout:
            print("⏰ Request timed out (server might be slow/down)")
        except requests.exceptions.ConnectionError:
            print("🔌 Connection error (server might be down)")
        except Exception as e:
            print(f"❌ Error: {e}")
    
    print("\n" + "=" * 60)
    print("🔍 DIAGNOSIS:")
    print("✅ If you see 'x-render-routing: no-server' -> Render deployment failed")
    print("✅ If you see 404 on all endpoints -> App not loading properly")
    print("✅ If you see 200/302 on OAuth -> OAuth endpoints are working!")
    print("✅ If you see timeouts -> Render might be sleeping (free tier)")

if __name__ == "__main__":
    test_oauth_endpoints()