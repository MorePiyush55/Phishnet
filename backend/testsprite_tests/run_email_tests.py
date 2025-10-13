"""
TestSprite Configuration and Test Runner
Automated testing for Gmail/Outlook email integration
"""

import subprocess
import sys
import json
from pathlib import Path
from datetime import datetime


class TestSpriteRunner:
    """TestSprite test execution manager"""
    
    def __init__(self):
        self.backend_path = Path(__file__).parent
        self.test_results = []
        
    def run_integration_tests(self):
        """Run complete email integration tests"""
        print("=" * 80)
        print("🧪 TESTSPRITE: Email Integration Test Suite")
        print("=" * 80)
        print(f"Started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print()
        
        # Test scenarios
        test_scenarios = [
            {
                "name": "Gmail OAuth Connection",
                "file": "tests/integration/test_email_integration_full.py",
                "test": "test_gmail_oauth_connection",
                "description": "Verify Gmail OAuth2 authentication"
            },
            {
                "name": "Email Retrieval",
                "file": "tests/integration/test_email_integration_full.py",
                "test": "test_email_retrieval_realtime",
                "description": "Confirm real-time email fetching"
            },
            {
                "name": "Phishing Analysis",
                "file": "tests/integration/test_email_integration_full.py",
                "test": "test_phishing_analysis_per_email",
                "description": "Validate phishing detection per email"
            },
            {
                "name": "Dashboard Display",
                "file": "tests/integration/test_email_integration_full.py",
                "test": "test_dashboard_display_accuracy",
                "description": "Check dashboard score accuracy"
            },
            {
                "name": "Real-time Updates",
                "file": "tests/integration/test_email_integration_full.py",
                "test": "test_realtime_updates",
                "description": "Verify automatic email detection"
            },
            {
                "name": "End-to-End Flow",
                "file": "tests/integration/test_email_integration_full.py",
                "test": "test_end_to_end_flow",
                "description": "Complete integration workflow"
            }
        ]
        
        # Run each test scenario
        passed = 0
        failed = 0
        
        for i, scenario in enumerate(test_scenarios, 1):
            print(f"\n[{i}/{len(test_scenarios)}] Testing: {scenario['name']}")
            print(f"Description: {scenario['description']}")
            print("-" * 80)
            
            try:
                # Run pytest for specific test
                cmd = [
                    sys.executable,
                    "-m", "pytest",
                    scenario['file'],
                    f"-k", scenario['test'],
                    "-v",
                    "-s",
                    "--tb=short"
                ]
                
                result = subprocess.run(
                    cmd,
                    cwd=self.backend_path,
                    capture_output=True,
                    text=True,
                    timeout=60
                )
                
                if result.returncode == 0:
                    print(f"✅ PASSED: {scenario['name']}")
                    passed += 1
                    self.test_results.append({
                        "scenario": scenario['name'],
                        "status": "PASSED",
                        "output": result.stdout
                    })
                else:
                    print(f"❌ FAILED: {scenario['name']}")
                    print(f"Error: {result.stderr}")
                    failed += 1
                    self.test_results.append({
                        "scenario": scenario['name'],
                        "status": "FAILED",
                        "error": result.stderr
                    })
                    
            except subprocess.TimeoutExpired:
                print(f"⏱️ TIMEOUT: {scenario['name']}")
                failed += 1
                self.test_results.append({
                    "scenario": scenario['name'],
                    "status": "TIMEOUT"
                })
            except Exception as e:
                print(f"⚠️ ERROR: {scenario['name']} - {str(e)}")
                failed += 1
                self.test_results.append({
                    "scenario": scenario['name'],
                    "status": "ERROR",
                    "error": str(e)
                })
        
        # Summary
        print("\n" + "=" * 80)
        print("📊 TEST SUMMARY")
        print("=" * 80)
        print(f"Total Tests: {len(test_scenarios)}")
        print(f"✅ Passed: {passed}")
        print(f"❌ Failed: {failed}")
        print(f"Success Rate: {(passed / len(test_scenarios) * 100):.1f}%")
        print(f"\nCompleted at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        
        # Save results
        self.save_results()
        
        return passed, failed
    
    def save_results(self):
        """Save test results to file"""
        results_dir = self.backend_path / "testsprite_tests" / "tmp"
        results_dir.mkdir(parents=True, exist_ok=True)
        
        results_file = results_dir / f"test_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        with open(results_file, 'w') as f:
            json.dump({
                "timestamp": datetime.now().isoformat(),
                "total_tests": len(self.test_results),
                "passed": sum(1 for r in self.test_results if r["status"] == "PASSED"),
                "failed": sum(1 for r in self.test_results if r["status"] in ["FAILED", "ERROR", "TIMEOUT"]),
                "results": self.test_results
            }, f, indent=2)
        
        print(f"\n📄 Results saved to: {results_file}")
    
    def run_quick_test(self):
        """Run quick smoke test"""
        print("=" * 80)
        print("🚀 TESTSPRITE: Quick Smoke Test")
        print("=" * 80)
        
        cmd = [
            sys.executable,
            "-m", "pytest",
            "tests/integration/test_email_integration_full.py",
            "-v",
            "--tb=short",
            "-x"  # Stop on first failure
        ]
        
        result = subprocess.run(cmd, cwd=self.backend_path)
        
        return result.returncode == 0


def main():
    """Main test runner"""
    runner = TestSpriteRunner()
    
    # Check if pytest is installed
    try:
        import pytest
        print(f"✓ pytest version: {pytest.__version__}")
    except ImportError:
        print("❌ pytest not installed. Installing...")
        subprocess.run([sys.executable, "-m", "pip", "install", "pytest", "pytest-asyncio"])
    
    print()
    
    # Run full test suite
    passed, failed = runner.run_integration_tests()
    
    # Exit with appropriate code
    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    main()
