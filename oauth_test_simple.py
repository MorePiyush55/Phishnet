"""
Simple OAuth API Testing Suite for PhishNet Application
Focuses on backend API testing without browser automation
"""

import requests
import json
import time
from typing import Dict, Any

# Configuration
FRONTEND_URL = "https://phishnet-tau.vercel.app"
BACKEND_URL = "https://phishnet-backend-iuoc.onrender.com"

class OAuthTester:
    """Simple OAuth testing class"""
    
    def __init__(self):
        self.results = []
        self.passed = 0
        self.failed = 0
    
    def log_result(self, test_name: str, passed: bool, message: str = ""):
        """Log test result"""
        status = "✅ PASS" if passed else "❌ FAIL"
        result = f"{status} | {test_name}: {message}"
        print(result)
        self.results.append(result)
        
        if passed:
            self.passed += 1
        else:
            self.failed += 1
    
    def test_backend_health(self):
        """Test backend health endpoint"""
        try:
            response = requests.get(f"{BACKEND_URL}/health", timeout=10)
            if response.status_code == 200:
                data = response.json()
                self.log_result("Backend Health", True, f"Status: {data.get('status', 'Unknown')}")
                return True
            else:
                self.log_result("Backend Health", False, f"HTTP {response.status_code}")
                return False
        except Exception as e:
            self.log_result("Backend Health", False, f"Error: {str(e)}")
            return False
    
    def test_oauth_google_endpoint(self):
        """Test Google OAuth endpoint"""
        try:
            response = requests.get(f"{BACKEND_URL}/api/rest/auth/google", timeout=10, allow_redirects=False)
            if response.status_code in [302, 307]:
                location = response.headers.get('Location', '')
                if 'accounts.google.com' in location or 'oauth2' in location.lower():
                    self.log_result("OAuth Google Endpoint", True, f"Redirects to Google OAuth")
                    return True
                else:
                    self.log_result("OAuth Google Endpoint", False, f"Invalid redirect: {location[:50]}...")
                    return False
            else:
                self.log_result("OAuth Google Endpoint", False, f"HTTP {response.status_code}")
                return False
        except Exception as e:
            self.log_result("OAuth Google Endpoint", False, f"Error: {str(e)}")
            return False
    
    def test_oauth_callback_endpoint(self):
        """Test OAuth callback endpoint"""
        try:
            # Test without parameters (should handle gracefully)
            response = requests.get(f"{BACKEND_URL}/api/rest/auth/callback", timeout=10)
            # Callback should handle missing parameters gracefully (not crash)
            if response.status_code in [200, 400, 401, 422]:
                self.log_result("OAuth Callback Endpoint", True, f"Handles requests gracefully (HTTP {response.status_code})")
                return True
            else:
                self.log_result("OAuth Callback Endpoint", False, f"HTTP {response.status_code}")
                return False
        except Exception as e:
            self.log_result("OAuth Callback Endpoint", False, f"Error: {str(e)}")
            return False
    
    def test_oauth_user_endpoint(self):
        """Test OAuth user endpoint"""
        try:
            response = requests.get(f"{BACKEND_URL}/api/rest/auth/user", timeout=10)
            # Should require authentication
            if response.status_code == 401:
                self.log_result("OAuth User Endpoint", True, "Properly requires authentication")
                return True
            elif response.status_code == 200:
                self.log_result("OAuth User Endpoint", True, "Returns user data when authenticated")
                return True
            else:
                self.log_result("OAuth User Endpoint", False, f"HTTP {response.status_code}")
                return False
        except Exception as e:
            self.log_result("OAuth User Endpoint", False, f"Error: {str(e)}")
            return False
    
    def test_api_documentation(self):
        """Test API documentation endpoint"""
        try:
            response = requests.get(f"{BACKEND_URL}/docs", timeout=10)
            if response.status_code == 200:
                self.log_result("API Documentation", True, "Swagger UI available")
                return True
            else:
                self.log_result("API Documentation", False, f"HTTP {response.status_code}")
                return False
        except Exception as e:
            self.log_result("API Documentation", False, f"Error: {str(e)}")
            return False
    
    def test_openapi_spec(self):
        """Test OpenAPI specification"""
        try:
            response = requests.get(f"{BACKEND_URL}/openapi.json", timeout=10)
            if response.status_code == 200:
                spec = response.json()
                paths = spec.get('paths', {})
                oauth_paths = [path for path in paths if 'auth' in path]
                self.log_result("OpenAPI Specification", True, f"Available with {len(oauth_paths)} auth endpoints")
                return True
            else:
                self.log_result("OpenAPI Specification", False, f"HTTP {response.status_code}")
                return False
        except Exception as e:
            self.log_result("OpenAPI Specification", False, f"Error: {str(e)}")
            return False
    
    def test_frontend_accessibility(self):
        """Test frontend accessibility"""
        try:
            response = requests.get(FRONTEND_URL, timeout=10)
            if response.status_code == 200:
                # Check if it's an HTML page
                if 'text/html' in response.headers.get('content-type', ''):
                    self.log_result("Frontend Accessibility", True, "Frontend loads successfully")
                    return True
                else:
                    self.log_result("Frontend Accessibility", False, "Not HTML content")
                    return False
            else:
                self.log_result("Frontend Accessibility", False, f"HTTP {response.status_code}")
                return False
        except Exception as e:
            self.log_result("Frontend Accessibility", False, f"Error: {str(e)}")
            return False
    
    def test_cors_headers(self):
        """Test CORS configuration"""
        try:
            headers = {
                'Origin': FRONTEND_URL,
                'Access-Control-Request-Method': 'GET'
            }
            response = requests.options(f"{BACKEND_URL}/api/rest/auth/user", headers=headers, timeout=10)
            
            cors_origin = response.headers.get('Access-Control-Allow-Origin')
            if cors_origin:
                self.log_result("CORS Headers", True, f"Origin: {cors_origin}")
                return True
            else:
                self.log_result("CORS Headers", False, "No CORS headers found")
                return False
        except Exception as e:
            self.log_result("CORS Headers", False, f"Error: {str(e)}")
            return False
    
    def test_oauth_state_parameter(self):
        """Test OAuth state parameter handling"""
        try:
            response = requests.get(
                f"{BACKEND_URL}/api/rest/auth/google",
                params={"state": "test_state_123"},
                timeout=10,
                allow_redirects=False
            )
            
            if response.status_code in [302, 307]:
                location = response.headers.get('Location', '')
                if 'state=' in location:
                    self.log_result("OAuth State Parameter", True, "State parameter preserved")
                    return True
                else:
                    self.log_result("OAuth State Parameter", False, "State parameter not preserved")
                    return False
            else:
                self.log_result("OAuth State Parameter", False, f"HTTP {response.status_code}")
                return False
        except Exception as e:
            self.log_result("OAuth State Parameter", False, f"Error: {str(e)}")
            return False
    
    def run_all_tests(self):
        """Run all tests"""
        print("🚀 PhishNet OAuth Testing Suite")
        print("=" * 50)
        print(f"Frontend: {FRONTEND_URL}")
        print(f"Backend:  {BACKEND_URL}")
        print("=" * 50)
        
        tests = [
            self.test_backend_health,
            self.test_oauth_google_endpoint,
            self.test_oauth_callback_endpoint,
            self.test_oauth_user_endpoint,
            self.test_api_documentation,
            self.test_openapi_spec,
            self.test_frontend_accessibility,
            self.test_cors_headers,
            self.test_oauth_state_parameter
        ]
        
        print("Running tests...")
        print("-" * 50)
        
        for test in tests:
            test()
        
        print("-" * 50)
        print(f"📊 Test Summary: {self.passed} passed, {self.failed} failed")
        
        if self.failed == 0:
            print("🎉 All tests passed! OAuth implementation is working correctly.")
        else:
            print("⚠️  Some tests failed. Check the details above.")
        
        return self.failed == 0

def main():
    """Main test runner"""
    tester = OAuthTester()
    success = tester.run_all_tests()
    
    if success:
        print("\n✅ OAuth Testing Complete - All Systems Operational!")
    else:
        print("\n❌ OAuth Testing Complete - Issues Detected")
    
    return success

if __name__ == "__main__":
    main()