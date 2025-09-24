"""
E2E Test Runner and Configuration

Centralized test runner for all end-to-end test suites:
- Complete flow testing
- Privacy compliance testing
- Security testing
- Performance testing

Provides unified test execution, reporting, and configuration management.
"""

import pytest
import asyncio
import json
import sys
import os
from datetime import datetime, timedelta
from typing import Dict, List, Any
import logging
from pathlib import Path

# Import all test suites
from test_complete_flow import *
from test_privacy_compliance import *
from test_security import *
from test_performance import *

# Setup logging for test runner
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class E2ETestRunner:
    """Centralized E2E test runner."""
    
    def __init__(self, config_path: str = "e2e_test_config.json"):
        """Initialize test runner with configuration."""
        self.config_path = config_path
        self.config = self._load_config()
        self.results = {}
        self.start_time = None
        self.end_time = None
    
    def _load_config(self) -> Dict[str, Any]:
        """Load test configuration."""
        default_config = {
            "test_suites": {
                "complete_flow": {
                    "enabled": True,
                    "timeout": 300,
                    "parallel": False,
                    "test_files": ["test_complete_flow.py"]
                },
                "privacy_compliance": {
                    "enabled": True,
                    "timeout": 180,
                    "parallel": True,
                    "test_files": ["test_privacy_compliance.py"]
                },
                "security": {
                    "enabled": True,
                    "timeout": 240,
                    "parallel": True,
                    "test_files": ["test_security.py"]
                },
                "performance": {
                    "enabled": True,
                    "timeout": 600,
                    "parallel": False,
                    "test_files": ["test_performance.py"]
                }
            },
            "reporting": {
                "generate_html_report": True,
                "generate_json_report": True,
                "generate_junit_xml": True,
                "save_logs": True
            },
            "environment": {
                "test_database": "test.db",
                "api_base_url": "http://localhost:8000",
                "test_timeout": 30,
                "max_retries": 3
            },
            "performance_thresholds": {
                "api_response_time_ms": 2000,
                "database_query_time_ms": 100,
                "memory_usage_mb": 500,
                "cpu_usage_percent": 80
            }
        }
        
        if os.path.exists(self.config_path):
            try:
                with open(self.config_path, "r") as f:
                    config = json.load(f)
                # Merge with defaults
                return {**default_config, **config}
            except Exception as e:
                logger.warning(f"Could not load config file: {e}. Using defaults.")
        
        return default_config
    
    def _save_config(self):
        """Save current configuration to file."""
        with open(self.config_path, "w") as f:
            json.dump(self.config, f, indent=2)
    
    async def run_test_suite(self, suite_name: str) -> Dict[str, Any]:
        """Run a specific test suite."""
        if suite_name not in self.config["test_suites"]:
            raise ValueError(f"Unknown test suite: {suite_name}")
        
        suite_config = self.config["test_suites"][suite_name]
        
        if not suite_config["enabled"]:
            logger.info(f"Test suite {suite_name} is disabled, skipping")
            return {"status": "skipped", "reason": "disabled"}
        
        logger.info(f"Running test suite: {suite_name}")
        
        # Build pytest arguments
        pytest_args = [
            "-v",
            "--tb=short",
            f"--timeout={suite_config['timeout']}",
            "--disable-warnings"
        ]
        
        # Add reporting options
        if self.config["reporting"]["generate_html_report"]:
            pytest_args.extend([
                "--html=reports/html_report.html",
                "--self-contained-html"
            ])
        
        if self.config["reporting"]["generate_junit_xml"]:
            pytest_args.extend([
                f"--junit-xml=reports/{suite_name}_junit.xml"
            ])
        
        # Add parallel execution if configured
        if suite_config.get("parallel", False):
            pytest_args.extend(["-n", "auto"])
        
        # Add test files
        for test_file in suite_config["test_files"]:
            pytest_args.append(test_file)
        
        # Run tests
        start_time = datetime.utcnow()
        exit_code = pytest.main(pytest_args)
        end_time = datetime.utcnow()
        
        duration = (end_time - start_time).total_seconds()
        
        result = {
            "status": "passed" if exit_code == 0 else "failed",
            "exit_code": exit_code,
            "start_time": start_time.isoformat(),
            "end_time": end_time.isoformat(),
            "duration_seconds": duration
        }
        
        logger.info(f"Test suite {suite_name} completed with status: {result['status']}")
        
        return result
    
    async def run_all_suites(self) -> Dict[str, Any]:
        """Run all enabled test suites."""
        self.start_time = datetime.utcnow()
        logger.info("Starting E2E test execution")
        
        # Create reports directory
        Path("reports").mkdir(exist_ok=True)
        
        # Run each test suite
        for suite_name in self.config["test_suites"].keys():
            try:
                result = await self.run_test_suite(suite_name)
                self.results[suite_name] = result
            except Exception as e:
                logger.error(f"Error running test suite {suite_name}: {e}")
                self.results[suite_name] = {
                    "status": "error",
                    "error": str(e),
                    "start_time": datetime.utcnow().isoformat(),
                    "end_time": datetime.utcnow().isoformat(),
                    "duration_seconds": 0
                }
        
        self.end_time = datetime.utcnow()
        
        # Generate summary report
        summary = self._generate_summary_report()
        
        # Save results
        if self.config["reporting"]["generate_json_report"]:
            await self._save_json_report(summary)
        
        return summary
    
    def _generate_summary_report(self) -> Dict[str, Any]:
        """Generate summary report of all test results."""
        total_suites = len(self.results)
        passed_suites = len([r for r in self.results.values() if r.get("status") == "passed"])
        failed_suites = len([r for r in self.results.values() if r.get("status") == "failed"])
        skipped_suites = len([r for r in self.results.values() if r.get("status") == "skipped"])
        error_suites = len([r for r in self.results.values() if r.get("status") == "error"])
        
        total_duration = (self.end_time - self.start_time).total_seconds() if self.end_time and self.start_time else 0
        
        summary = {
            "test_execution": {
                "start_time": self.start_time.isoformat() if self.start_time else None,
                "end_time": self.end_time.isoformat() if self.end_time else None,
                "total_duration_seconds": total_duration
            },
            "summary_stats": {
                "total_suites": total_suites,
                "passed_suites": passed_suites,
                "failed_suites": failed_suites,
                "skipped_suites": skipped_suites,
                "error_suites": error_suites,
                "success_rate": (passed_suites / total_suites * 100) if total_suites > 0 else 0
            },
            "suite_results": self.results,
            "configuration": self.config,
            "recommendations": self._generate_recommendations()
        }
        
        return summary
    
    def _generate_recommendations(self) -> List[str]:
        """Generate recommendations based on test results."""
        recommendations = []
        
        # Check for failures
        failed_suites = [name for name, result in self.results.items() if result.get("status") == "failed"]
        if failed_suites:
            recommendations.append(f"Investigate failures in: {', '.join(failed_suites)}")
        
        # Check for long-running tests
        slow_suites = [
            name for name, result in self.results.items() 
            if result.get("duration_seconds", 0) > 300  # 5 minutes
        ]
        if slow_suites:
            recommendations.append(f"Consider optimizing slow test suites: {', '.join(slow_suites)}")
        
        # Check success rate
        success_rate = len([r for r in self.results.values() if r.get("status") == "passed"]) / len(self.results) * 100 if self.results else 0
        if success_rate < 100:
            recommendations.append(f"Test success rate is {success_rate:.1f}% - aim for 100%")
        
        if not recommendations:
            recommendations.append("All tests passed successfully!")
        
        return recommendations
    
    async def _save_json_report(self, summary: Dict[str, Any]):
        """Save JSON test report."""
        report_file = f"reports/e2e_test_report_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json"
        
        with open(report_file, "w") as f:
            json.dump(summary, f, indent=2, default=str)
        
        logger.info(f"JSON report saved to: {report_file}")
    
    def print_summary(self):
        """Print test summary to console."""
        if not self.results:
            print("No test results available")
            return
        
        print("\n" + "="*70)
        print("E2E TEST EXECUTION SUMMARY")
        print("="*70)
        
        total_suites = len(self.results)
        passed_suites = len([r for r in self.results.values() if r.get("status") == "passed"])
        failed_suites = len([r for r in self.results.values() if r.get("status") == "failed"])
        
        print(f"Total Suites: {total_suites}")
        print(f"Passed: {passed_suites}")
        print(f"Failed: {failed_suites}")
        print(f"Success Rate: {(passed_suites / total_suites * 100):.1f}%" if total_suites > 0 else "N/A")
        
        if self.start_time and self.end_time:
            duration = (self.end_time - self.start_time).total_seconds()
            print(f"Total Duration: {duration:.1f} seconds")
        
        print("\nSuite Details:")
        print("-" * 40)
        
        for suite_name, result in self.results.items():
            status = result.get("status", "unknown")
            duration = result.get("duration_seconds", 0)
            
            status_symbol = {
                "passed": "✓",
                "failed": "✗",
                "skipped": "⚠",
                "error": "⚡"
            }.get(status, "?")
            
            print(f"{status_symbol} {suite_name:20} {status:8} ({duration:.1f}s)")
        
        print("\n" + "="*70)

class E2ETestConfig:
    """E2E test configuration management."""
    
    @staticmethod
    def create_default_config(config_path: str = "e2e_test_config.json"):
        """Create default configuration file."""
        runner = E2ETestRunner(config_path)
        runner._save_config()
        print(f"Default configuration saved to: {config_path}")
    
    @staticmethod
    def validate_config(config_path: str = "e2e_test_config.json") -> bool:
        """Validate configuration file."""
        try:
            runner = E2ETestRunner(config_path)
            
            # Check required sections
            required_sections = ["test_suites", "reporting", "environment"]
            for section in required_sections:
                if section not in runner.config:
                    print(f"Missing required section: {section}")
                    return False
            
            # Check test suite configurations
            for suite_name, suite_config in runner.config["test_suites"].items():
                required_keys = ["enabled", "timeout", "test_files"]
                for key in required_keys:
                    if key not in suite_config:
                        print(f"Missing required key '{key}' in suite '{suite_name}'")
                        return False
            
            print("Configuration is valid")
            return True
            
        except Exception as e:
            print(f"Configuration validation failed: {e}")
            return False

# CLI interface for test runner
async def main():
    """Main CLI interface."""
    import argparse
    
    parser = argparse.ArgumentParser(description="E2E Test Runner for PhishNet")
    parser.add_argument("--config", default="e2e_test_config.json", help="Configuration file path")
    parser.add_argument("--suite", help="Run specific test suite")
    parser.add_argument("--create-config", action="store_true", help="Create default configuration")
    parser.add_argument("--validate-config", action="store_true", help="Validate configuration")
    parser.add_argument("--list-suites", action="store_true", help="List available test suites")
    
    args = parser.parse_args()
    
    # Handle configuration commands
    if args.create_config:
        E2ETestConfig.create_default_config(args.config)
        return
    
    if args.validate_config:
        E2ETestConfig.validate_config(args.config)
        return
    
    # Initialize test runner
    runner = E2ETestRunner(args.config)
    
    if args.list_suites:
        print("Available test suites:")
        for suite_name, suite_config in runner.config["test_suites"].items():
            status = "enabled" if suite_config["enabled"] else "disabled"
            print(f"  {suite_name}: {status}")
        return
    
    try:
        if args.suite:
            # Run specific suite
            result = await runner.run_test_suite(args.suite)
            print(f"Suite {args.suite} completed with status: {result['status']}")
        else:
            # Run all suites
            summary = await runner.run_all_suites()
            runner.print_summary()
            
            # Exit with error code if any tests failed
            failed_suites = len([r for r in runner.results.values() if r.get("status") == "failed"])
            error_suites = len([r for r in runner.results.values() if r.get("status") == "error"])
            
            if failed_suites > 0 or error_suites > 0:
                sys.exit(1)
    
    except KeyboardInterrupt:
        logger.info("Test execution interrupted by user")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Test execution failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    # Create default configuration on first run
    if not os.path.exists("e2e_test_config.json"):
        E2ETestConfig.create_default_config()
    
    # Run tests
    asyncio.run(main())