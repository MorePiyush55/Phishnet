#!/usr/bin/env python3
"""
Simple Test Runner for PhishNet Background Worker System
Quick validation of core functionality.
"""

import asyncio
import time
import requests
from typing import Dict, Any
import json

class QuickTestRunner:
    """Quick tests for basic functionality validation."""
    
    def __init__(self, base_url: str = "http://localhost:8000"):
        self.base_url = base_url
        
    def test_api_health(self) -> bool:
        """Test if API is responding."""
        try:
            response = requests.get(f"{self.base_url}/health", timeout=5)
            return response.status_code == 200
        except Exception:
            return False
    
    def test_worker_dashboard(self) -> bool:
        """Test worker dashboard accessibility."""
        try:
            response = requests.get(f"{self.base_url}/api/v1/workers/dashboard", timeout=5)
            return response.status_code == 200
        except Exception:
            return False
    
    def test_job_submission(self) -> Dict[str, Any]:
        """Test submitting a single job."""
        test_email = {
            "subject": "Test Email - Security Alert",
            "sender": "test@example.com", 
            "content": "This is a test email for validation. Please click http://suspicious-link.com",
            "analysis_type": "quick"
        }
        
        try:
            response = requests.post(
                f"{self.base_url}/api/v1/analysis/submit",
                json=test_email,
                timeout=10
            )
            
            if response.status_code == 200:
                result = response.json()
                return {
                    "success": True,
                    "job_id": result.get("job_id"),
                    "status": result.get("status")
                }
            else:
                return {"success": False, "error": f"HTTP {response.status_code}"}
                
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def test_job_status(self, job_id: str) -> Dict[str, Any]:
        """Test job status retrieval."""
        try:
            response = requests.get(
                f"{self.base_url}/api/v1/analysis/status/{job_id}",
                timeout=5
            )
            
            if response.status_code == 200:
                return {"success": True, "status": response.json()}
            else:
                return {"success": False, "error": f"HTTP {response.status_code}"}
                
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def test_bulk_submission(self, num_jobs: int = 10) -> Dict[str, Any]:
        """Test bulk job submission."""
        emails = []
        for i in range(num_jobs):
            emails.append({
                "subject": f"Test Email #{i}",
                "sender": f"test{i}@example.com",
                "content": f"Test content {i}",
                "analysis_type": "quick"
            })
        
        try:
            response = requests.post(
                f"{self.base_url}/api/v1/analysis/submit-bulk",
                json={
                    "emails": emails,
                    "analysis_type": "quick",
                    "priority": "normal"
                },
                timeout=30
            )
            
            if response.status_code == 200:
                result = response.json()
                return {
                    "success": True,
                    "batch_id": result.get("batch_id"),
                    "job_ids": result.get("job_ids", []),
                    "total_jobs": result.get("total_jobs", 0)
                }
            else:
                return {"success": False, "error": f"HTTP {response.status_code}"}
                
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def test_worker_stats(self) -> Dict[str, Any]:
        """Test worker statistics endpoint."""
        try:
            response = requests.get(f"{self.base_url}/api/v1/workers/stats", timeout=5)
            
            if response.status_code == 200:
                return {"success": True, "stats": response.json()}
            else:
                return {"success": False, "error": f"HTTP {response.status_code}"}
                
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    async def run_quick_tests(self) -> Dict[str, Any]:
        """Run all quick validation tests."""
        print("🚀 Running PhishNet Quick Validation Tests")
        print("=" * 50)
        
        results = {
            "timestamp": time.time(),
            "tests": {}
        }
        
        # Test 1: API Health
        print("1. Testing API health...")
        health_result = self.test_api_health()
        results["tests"]["api_health"] = health_result
        print(f"   ✅ API Health: {'PASS' if health_result else 'FAIL'}")
        
        if not health_result:
            print("   ❌ API is not responding. Check if the server is running.")
            return results
        
        # Test 2: Worker Dashboard
        print("2. Testing worker dashboard...")
        dashboard_result = self.test_worker_dashboard()
        results["tests"]["worker_dashboard"] = dashboard_result
        print(f"   ✅ Worker Dashboard: {'PASS' if dashboard_result else 'FAIL'}")
        
        # Test 3: Job Submission
        print("3. Testing job submission...")
        submission_result = self.test_job_submission()
        results["tests"]["job_submission"] = submission_result
        print(f"   ✅ Job Submission: {'PASS' if submission_result.get('success') else 'FAIL'}")
        
        if submission_result.get("success"):
            job_id = submission_result.get("job_id")
            print(f"      Job ID: {job_id}")
            
            # Test 4: Job Status
            print("4. Testing job status...")
            await asyncio.sleep(2)  # Wait a bit for job to start
            status_result = self.test_job_status(job_id)
            results["tests"]["job_status"] = status_result
            print(f"   ✅ Job Status: {'PASS' if status_result.get('success') else 'FAIL'}")
            
            if status_result.get("success"):
                job_status = status_result["status"]
                print(f"      Status: {job_status.get('status')}")
                print(f"      Progress: {job_status.get('progress')}%")
        
        # Test 5: Worker Stats
        print("5. Testing worker stats...")
        stats_result = self.test_worker_stats()
        results["tests"]["worker_stats"] = stats_result
        print(f"   ✅ Worker Stats: {'PASS' if stats_result.get('success') else 'FAIL'}")
        
        if stats_result.get("success"):
            stats = stats_result["stats"]
            print(f"      Active workers: {stats.get('active_workers', 0)}")
            print(f"      Total pending: {stats.get('total_pending', 0)}")
        
        # Test 6: Bulk Submission
        print("6. Testing bulk submission (10 jobs)...")
        bulk_result = self.test_bulk_submission(10)
        results["tests"]["bulk_submission"] = bulk_result
        print(f"   ✅ Bulk Submission: {'PASS' if bulk_result.get('success') else 'FAIL'}")
        
        if bulk_result.get("success"):
            print(f"      Batch ID: {bulk_result.get('batch_id')}")
            print(f"      Jobs created: {bulk_result.get('total_jobs')}")
        
        # Summary
        print("\n📊 Test Summary")
        print("-" * 20)
        passed_tests = sum(1 for test in results["tests"].values() if 
                          (isinstance(test, bool) and test) or 
                          (isinstance(test, dict) and test.get('success')))
        total_tests = len(results["tests"])
        
        print(f"Passed: {passed_tests}/{total_tests}")
        print(f"Success Rate: {(passed_tests/total_tests*100):.1f}%")
        
        if passed_tests == total_tests:
            print("🎉 All tests passed! System is operational.")
        else:
            print("⚠️  Some tests failed. Check the system configuration.")
        
        return results

def main():
    """Main function for CLI execution."""
    import argparse
    
    parser = argparse.ArgumentParser(description="PhishNet Quick Test Runner")
    parser.add_argument("--base-url", default="http://localhost:8000", 
                       help="Base URL for API testing")
    parser.add_argument("--output", help="Save results to JSON file")
    
    args = parser.parse_args()
    
    async def run_tests():
        test_runner = QuickTestRunner(args.base_url)
        results = await test_runner.run_quick_tests()
        
        if args.output:
            with open(args.output, 'w') as f:
                json.dump(results, f, indent=2)
            print(f"\n💾 Results saved to {args.output}")
        
        return results
    
    return asyncio.run(run_tests())

if __name__ == "__main__":
    main()