#!/usr/bin/env python3
"""
Simple test script to check backend health endpoints
"""

import requests
import json

def test_endpoint(url, description):
    """Test a single endpoint"""
    try:
        print(f"\n🔍 Testing {description}: {url}")
        response = requests.get(url, timeout=10)
        print(f"   Status: {response.status_code}")
        
        if response.status_code == 200:
            try:
                data = response.json()
                print(f"   Response: {json.dumps(data, indent=2)}")
            except:
                print(f"   Response: {response.text}")
        else:
            print(f"   Error: {response.text}")
            
    except requests.exceptions.ConnectionError:
        print(f"   ❌ Connection failed - server may not be running")
    except Exception as e:
        print(f"   ❌ Error: {str(e)}")

def main():
    """Test all important endpoints"""
    base_url = "http://localhost:8000"
    
    print("🚀 Testing PhishNet Backend Endpoints")
    print("=" * 50)
    
    # Test basic endpoints
    test_endpoint(f"{base_url}/", "Root endpoint")
    test_endpoint(f"{base_url}/health", "Basic health check")
    
    # Test our fixed health endpoints
    test_endpoint(f"{base_url}/health/", "Advanced health endpoint")
    test_endpoint(f"{base_url}/health/detailed", "Detailed health check")
    test_endpoint(f"{base_url}/health/readiness", "Readiness probe")
    test_endpoint(f"{base_url}/health/liveness", "Liveness probe")
    
    # Test email analysis endpoint
    test_endpoint(f"{base_url}/api/analyze/", "Email analysis")
    
    print("\n" + "=" * 50)
    print("✅ Health check testing completed!")

if __name__ == "__main__":
    main()