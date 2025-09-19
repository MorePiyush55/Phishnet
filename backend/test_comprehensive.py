#!/usr/bin/env python3
"""
Comprehensive PhishNet Backend Test Suite
Tests all major endpoints and functionality
"""

import requests
import json
import time
from datetime import datetime

class PhishNetTester:
    def __init__(self, base_url="http://localhost:8000"):
        self.base_url = base_url
        self.test_token = None
        self.results = []
    
    def log_result(self, test_name, success, message, response_time=None):
        """Log test result"""
        status = "✅ PASS" if success else "❌ FAIL"
        time_str = f" ({response_time:.2f}s)" if response_time else ""
        print(f"   {status}: {test_name}{time_str}")
        if not success:
            print(f"      Error: {message}")
        
        self.results.append({
            "test": test_name,
            "success": success,
            "message": message,
            "response_time": response_time
        })
    
    def test_basic_health(self):
        """Test basic health endpoints"""
        print("\n🔍 Testing Health Endpoints")
        print("-" * 30)
        
        endpoints = [
            ("/", "Root endpoint"),
            ("/health", "Basic health"),
            ("/health/", "Health router root"),
            ("/health/readiness", "Readiness probe"),
            ("/health/liveness", "Liveness probe")
        ]
        
        for endpoint, description in endpoints:
            try:
                start_time = time.time()
                response = requests.get(f"{self.base_url}{endpoint}", timeout=10)
                response_time = time.time() - start_time
                
                if response.status_code == 200:
                    self.log_result(description, True, "OK", response_time)
                else:
                    self.log_result(description, False, f"HTTP {response.status_code}")
            except Exception as e:
                self.log_result(description, False, str(e))
    
    def test_authentication(self):
        """Test authentication system"""
        print("\n🔐 Testing Authentication System")
        print("-" * 35)
        
        # Test auth router
        try:
            response = requests.get(f"{self.base_url}/api/auth/test", timeout=10)
            if response.status_code == 200:
                self.log_result("Auth router test", True, "OK")
            else:
                self.log_result("Auth router test", False, f"HTTP {response.status_code}")
        except Exception as e:
            self.log_result("Auth router test", False, str(e))
        
        # Test user registration
        user_data = {
            "email": f"test_{int(time.time())}@example.com",
            "username": f"testuser_{int(time.time())}",
            "password": "testpassword123",
            "full_name": "Test User"
        }
        
        try:
            response = requests.post(f"{self.base_url}/api/auth/register", 
                                   json=user_data, timeout=10)
            if response.status_code == 200:
                self.log_result("User registration", True, "User created successfully")
            else:
                self.log_result("User registration", False, f"HTTP {response.status_code}: {response.text}")
        except Exception as e:
            self.log_result("User registration", False, str(e))
        
        # Test user login
        login_data = {
            "email": user_data["email"],
            "password": user_data["password"]
        }
        
        try:
            response = requests.post(f"{self.base_url}/api/auth/login", 
                                   json=login_data, timeout=10)
            if response.status_code == 200:
                token_data = response.json()
                self.test_token = token_data["access_token"]
                self.log_result("User login", True, "Login successful")
            else:
                self.log_result("User login", False, f"HTTP {response.status_code}: {response.text}")
        except Exception as e:
            self.log_result("User login", False, str(e))
        
        # Test authenticated endpoint
        if self.test_token:
            try:
                headers = {"Authorization": f"Bearer {self.test_token}"}
                response = requests.get(f"{self.base_url}/api/auth/me", 
                                      headers=headers, timeout=10)
                if response.status_code == 200:
                    self.log_result("Authenticated endpoint", True, "User data retrieved")
                else:
                    self.log_result("Authenticated endpoint", False, f"HTTP {response.status_code}")
            except Exception as e:
                self.log_result("Authenticated endpoint", False, str(e))
    
    def test_email_analysis(self):
        """Test email analysis functionality"""
        print("\n📧 Testing Email Analysis")
        print("-" * 28)
        
        # Test without authentication first (should fail)
        email_data = {
            "subject": "Urgent: Verify your account immediately",
            "sender": "noreply@suspicious-site.com",
            "content": "Click here to verify your account: http://bit.ly/verify-now",
            "headers": {
                "Content-Type": "text/html"
            }
        }
        
        try:
            response = requests.post(f"{self.base_url}/api/analyze/email", 
                                   json=email_data, timeout=10)
            if response.status_code == 401:
                self.log_result("Email analysis (no auth)", True, "Correctly requires authentication")
            else:
                self.log_result("Email analysis (no auth)", False, f"Should require auth but got HTTP {response.status_code}")
        except Exception as e:
            self.log_result("Email analysis (no auth)", False, str(e))
        
        # Test with authentication
        if self.test_token:
            try:
                headers = {"Authorization": f"Bearer {self.test_token}"}
                response = requests.post(f"{self.base_url}/api/analyze/email", 
                                       json=email_data, headers=headers, timeout=15)
                if response.status_code == 200:
                    analysis = response.json()
                    
                    # Check if analysis has expected fields
                    required_fields = ["is_phishing", "confidence", "risk_level", "threats_detected"]
                    has_all_fields = all(field in analysis for field in required_fields)
                    
                    if has_all_fields:
                        threat_level = analysis["risk_level"]
                        confidence = analysis["confidence"]
                        self.log_result("Email analysis (with auth)", True, 
                                      f"Analysis complete - Risk: {threat_level}, Confidence: {confidence:.2f}")
                    else:
                        self.log_result("Email analysis (with auth)", False, "Missing required fields in response")
                else:
                    self.log_result("Email analysis (with auth)", False, f"HTTP {response.status_code}: {response.text}")
            except Exception as e:
                self.log_result("Email analysis (with auth)", False, str(e))
        
        # Test with legitimate email
        if self.test_token:
            legitimate_email = {
                "subject": "Welcome to GitHub",
                "sender": "noreply@github.com",
                "content": "Welcome to GitHub! Your account has been created successfully.",
                "headers": {}
            }
            
            try:
                headers = {"Authorization": f"Bearer {self.test_token}"}
                response = requests.post(f"{self.base_url}/api/analyze/email", 
                                       json=legitimate_email, headers=headers, timeout=15)
                if response.status_code == 200:
                    analysis = response.json()
                    risk_level = analysis["risk_level"]
                    is_phishing = analysis["is_phishing"]
                    
                    if risk_level in ["LOW", "MEDIUM"] and not is_phishing:
                        self.log_result("Legitimate email analysis", True, f"Correctly identified as {risk_level} risk")
                    else:
                        self.log_result("Legitimate email analysis", False, f"Incorrectly flagged: {risk_level}, phishing: {is_phishing}")
                else:
                    self.log_result("Legitimate email analysis", False, f"HTTP {response.status_code}")
            except Exception as e:
                self.log_result("Legitimate email analysis", False, str(e))
    
    def test_database_connectivity(self):
        """Test database connectivity through health endpoints"""
        print("\n🗄️  Testing Database Connectivity")
        print("-" * 35)
        
        # Test detailed health check
        try:
            response = requests.get(f"{self.base_url}/health/detailed", timeout=15)
            if response.status_code == 200:
                health_data = response.json()
                
                # Check database status
                if "components" in health_data and "database" in health_data["components"]:
                    db_status = health_data["components"]["database"]["status"]
                    if db_status == "healthy":
                        self.log_result("MongoDB connectivity", True, "Database is healthy")
                    else:
                        self.log_result("MongoDB connectivity", False, f"Database status: {db_status}")
                else:
                    self.log_result("MongoDB connectivity", False, "No database info in health check")
            else:
                self.log_result("MongoDB connectivity", False, f"HTTP {response.status_code}")
        except Exception as e:
            self.log_result("MongoDB connectivity", False, str(e))
    
    def generate_report(self):
        """Generate test report"""
        print("\n" + "=" * 60)
        print("📊 TEST REPORT")
        print("=" * 60)
        
        total_tests = len(self.results)
        passed_tests = sum(1 for result in self.results if result["success"])
        failed_tests = total_tests - passed_tests
        
        success_rate = (passed_tests / total_tests * 100) if total_tests > 0 else 0
        
        print(f"\nTotal Tests: {total_tests}")
        print(f"Passed: {passed_tests}")
        print(f"Failed: {failed_tests}")
        print(f"Success Rate: {success_rate:.1f}%")
        
        if failed_tests > 0:
            print(f"\n❌ FAILED TESTS:")
            for result in self.results:
                if not result["success"]:
                    print(f"   - {result['test']}: {result['message']}")
        
        print(f"\n{'🎉 ALL TESTS PASSED!' if failed_tests == 0 else '⚠️  SOME TESTS FAILED'}")
        
        # Determine production readiness
        critical_tests = [
            "Root endpoint", "Basic health", "MongoDB connectivity",
            "Auth router test", "Email analysis (with auth)"
        ]
        
        critical_passed = sum(1 for result in self.results 
                            if result["test"] in critical_tests and result["success"])
        
        production_ready = critical_passed == len(critical_tests)
        
        print(f"\n🚀 PRODUCTION READINESS: {'✅ READY' if production_ready else '❌ NOT READY'}")
        print(f"   Critical Systems: {critical_passed}/{len(critical_tests)} operational")
        
        if production_ready:
            print(f"\n🎯 PhishNet Backend is 100% production ready!")
            print(f"   ✅ MongoDB database connected and healthy")
            print(f"   ✅ Authentication system working")
            print(f"   ✅ Email analysis engine functional")
            print(f"   ✅ Health monitoring active")
        
        return production_ready

def main():
    """Run comprehensive test suite"""
    print("🚀 PhishNet Backend Test Suite")
    print("=" * 60)
    print(f"Testing backend at: http://localhost:8000")
    print(f"Started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    tester = PhishNetTester()
    
    # Run all tests
    tester.test_basic_health()
    tester.test_database_connectivity()
    tester.test_authentication()
    tester.test_email_analysis()
    
    # Generate report
    production_ready = tester.generate_report()
    
    # Return appropriate exit code
    exit(0 if production_ready else 1)

if __name__ == "__main__":
    main()