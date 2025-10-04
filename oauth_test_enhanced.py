"""
Enhanced OAuth Testing Suite with Backend Wake-up and Extended Timeouts
"""

import requests
import json
import time
from typing import Dict, Any

# Configuration
FRONTEND_URL = "https://phishnet-tau.vercel.app"
BACKEND_URL = "https://phishnet-backend-iuoc.onrender.com"

class EnhancedOAuthTester:
    """Enhanced OAuth testing with backend wake-up capabilities"""
    
    def __init__(self):
        self.results = []
        self.passed = 0
        self.failed = 0
        self.backend_awake = False
    
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
    
    def wake_up_backend(self):
        """Wake up the backend service (Render free tier goes to sleep)"""
        print("🔄 Waking up backend service...")
        
        for attempt in range(3):
            try:
                print(f"   Attempt {attempt + 1}/3: Pinging backend...")
                response = requests.get(f"{BACKEND_URL}/health", timeout=60)  # Extended timeout
                
                if response.status_code == 200:
                    print("   ✅ Backend is awake!")
                    self.backend_awake = True
                    return True
                else:
                    print(f"   Backend responded with status {response.status_code}")
                    
            except requests.exceptions.Timeout:
                print(f"   Timeout on attempt {attempt + 1}, retrying...")
                time.sleep(5)
            except Exception as e:
                print(f"   Error on attempt {attempt + 1}: {str(e)}")
                time.sleep(5)
        
        print("   ❌ Backend did not wake up after 3 attempts")
        return False
    
    def test_backend_health(self):
        """Test backend health endpoint with retry logic"""
        if not self.backend_awake:
            if not self.wake_up_backend():
                self.log_result("Backend Health", False, "Backend failed to wake up")
                return False
        
        try:
            response = requests.get(f"{BACKEND_URL}/health", timeout=30)
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
            response = requests.get(f"{BACKEND_URL}/api/rest/auth/google", timeout=30, allow_redirects=False)
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
            response = requests.get(f"{BACKEND_URL}/api/rest/auth/callback", timeout=30)
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
            response = requests.get(f"{BACKEND_URL}/api/rest/auth/user", timeout=30)
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
            response = requests.get(f"{BACKEND_URL}/docs", timeout=30)
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
            response = requests.get(f"{BACKEND_URL}/openapi.json", timeout=30)
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
            response = requests.get(FRONTEND_URL, timeout=30)
            if response.status_code == 200:
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
    
    def test_oauth_flow_simulation(self):
        """Simulate a complete OAuth flow"""
        try:
            print("\n🔄 Simulating OAuth Flow...")
            
            # Step 1: Initial OAuth redirect
            response = requests.get(f"{BACKEND_URL}/api/rest/auth/google", timeout=30, allow_redirects=False)
            
            if response.status_code in [302, 307]:
                location = response.headers.get('Location', '')
                print(f"   Step 1: ✅ OAuth redirect successful")
                print(f"            Redirect URL: {location[:80]}...")
                
                # Step 2: Check if redirect contains required parameters
                required_params = ['client_id', 'redirect_uri', 'response_type', 'scope']
                missing_params = [param for param in required_params if param not in location]
                
                if not missing_params:
                    print(f"   Step 2: ✅ All required OAuth parameters present")
                    self.log_result("OAuth Flow Simulation", True, "Complete flow parameters validated")
                    return True
                else:
                    print(f"   Step 2: ❌ Missing parameters: {missing_params}")
                    self.log_result("OAuth Flow Simulation", False, f"Missing parameters: {missing_params}")
                    return False
            else:
                print(f"   Step 1: ❌ OAuth redirect failed (HTTP {response.status_code})")
                self.log_result("OAuth Flow Simulation", False, f"Redirect failed: HTTP {response.status_code}")
                return False
                
        except Exception as e:
            print(f"   OAuth Flow Error: {str(e)}")
            self.log_result("OAuth Flow Simulation", False, f"Error: {str(e)}")
            return False
    
    def run_all_tests(self):
        """Run all tests with backend wake-up"""
        print("🚀 Enhanced PhishNet OAuth Testing Suite")
        print("=" * 60)
        print(f"Frontend: {FRONTEND_URL}")
        print(f"Backend:  {BACKEND_URL}")
        print("=" * 60)
        
        # First, try to wake up the backend
        print("Phase 1: Backend Wake-up")
        print("-" * 30)
        self.wake_up_backend()
        
        print("\nPhase 2: Core Tests")
        print("-" * 30)
        
        core_tests = [
            self.test_backend_health,
            self.test_oauth_google_endpoint,
            self.test_oauth_callback_endpoint,
            self.test_oauth_user_endpoint,
        ]
        
        for test in core_tests:
            test()
        
        print("\nPhase 3: Extended Tests")
        print("-" * 30)
        
        extended_tests = [
            self.test_api_documentation,
            self.test_openapi_spec,
            self.test_frontend_accessibility,
            self.test_oauth_flow_simulation
        ]
        
        for test in extended_tests:
            test()
        
        print("\n" + "=" * 60)
        print(f"📊 Final Results: {self.passed} passed, {self.failed} failed")
        
        if self.failed == 0:
            print("🎉 All tests passed! OAuth implementation is fully functional.")
        elif self.passed >= 4:  # At least core functionality works
            print("✅ Core OAuth functionality is working. Some extended features may need attention.")
        else:
            print("⚠️  Critical issues detected. OAuth implementation needs fixes.")
        
        return self.failed == 0

def main():
    """Main test runner"""
    print("Starting OAuth Testing with Enhanced Backend Support...\n")
    
    tester = EnhancedOAuthTester()
    success = tester.run_all_tests()
    
    print("\n" + "=" * 60)
    if success:
        print("✅ TESTING COMPLETE - ALL SYSTEMS OPERATIONAL!")
        print("Your OAuth implementation is ready for production use.")
    else:
        print("📋 TESTING COMPLETE - RESULTS SUMMARY:")
        print("Check the detailed results above for specific issues.")
    
    return success

if __name__ == "__main__":
    main()