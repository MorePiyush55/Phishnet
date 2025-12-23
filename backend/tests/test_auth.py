#!/usr/bin/env python3
"""
Test authentication endpoints
"""

import requests
import json

def test_auth_endpoints():
    """Test authentication system"""
    base_url = "http://localhost:8000"
    
    print("🔐 Testing Authentication System")
    print("=" * 50)
    
    # Test auth test endpoint
    try:
        print("\n🔍 Testing auth router...")
        response = requests.get(f"{base_url}/api/auth/test", timeout=10)
        print(f"   Status: {response.status_code}")
        if response.status_code == 200:
            print(f"   Response: {json.dumps(response.json(), indent=2)}")
        else:
            print(f"   Error: {response.text}")
    except Exception as e:
        print(f"   ❌ Error: {str(e)}")
    
    # Test user registration
    try:
        print("\n🔍 Testing user registration...")
        user_data = {
            "email": "test@example.com",
            "username": "testuser",
            "password": "testpassword123",
            "full_name": "Test User"
        }
        response = requests.post(f"{base_url}/api/auth/register", 
                               json=user_data, timeout=10)
        print(f"   Status: {response.status_code}")
        if response.status_code == 200:
            print(f"   User created: {json.dumps(response.json(), indent=2)}")
        else:
            print(f"   Error: {response.text}")
    except Exception as e:
        print(f"   ❌ Error: {str(e)}")
    
    # Test user login
    try:
        print("\n🔍 Testing user login...")
        login_data = {
            "email": "test@example.com",
            "password": "testpassword123"
        }
        response = requests.post(f"{base_url}/api/auth/login", 
                               json=login_data, timeout=10)
        print(f"   Status: {response.status_code}")
        if response.status_code == 200:
            token_data = response.json()
            print(f"   Login successful: {json.dumps(token_data, indent=2)}")
            
            # Test authenticated endpoint
            print("\n🔍 Testing authenticated endpoint...")
            token = token_data["access_token"]
            headers = {"Authorization": f"Bearer {token}"}
            
            response = requests.get(f"{base_url}/api/auth/me", 
                                  headers=headers, timeout=10)
            print(f"   Status: {response.status_code}")
            if response.status_code == 200:
                print(f"   User info: {json.dumps(response.json(), indent=2)}")
            else:
                print(f"   Error: {response.text}")
                
        else:
            print(f"   Error: {response.text}")
    except Exception as e:
        print(f"   ❌ Error: {str(e)}")
    
    print("\n" + "=" * 50)
    print("✅ Authentication testing completed!")

if __name__ == "__main__":
    test_auth_endpoints()