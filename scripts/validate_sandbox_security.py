#!/usr/bin/env python3
"""
Sandbox Security Validation CLI

Command-line tool to run security tests and validate sandbox configuration.
"""

import asyncio
import argparse
import json
import sys
from pathlib import Path
from datetime import datetime

from app.services.security_tester import security_tester


async def run_security_tests(test_type: str = "all", verbose: bool = False):
    """Run security tests."""
    print("🔒 PhishNet Sandbox Security Validation")
    print("=" * 50)
    
    if test_type == "all":
        print("Running complete security test suite...")
        suite = await security_tester.run_full_security_test_suite()
    else:
        print(f"Running {test_type} tests...")
        # Individual test category would be implemented here
        return
    
    # Print summary
    print("\n📊 Test Results Summary")
    print("-" * 30)
    print(f"Overall Status: {'✅ PASS' if suite.overall_status.value == 'pass' else '❌ FAIL'}")
    print(f"Security Score: {suite.security_score}/100")
    print(f"Total Tests: {suite.total_tests}")
    print(f"Passed: {suite.passed_tests}")
    print(f"Failed: {suite.failed_tests}")
    print(f"Errors: {suite.error_tests}")
    
    # Print compliance status
    print("\n🛡️ Compliance Status")
    print("-" * 20)
    for area, status in suite.compliance_status.items():
        status_icon = "✅" if status else "❌"
        print(f"{status_icon} {area.replace('_', ' ').title()}")
    
    if verbose:
        # Print detailed results
        print("\n📋 Detailed Test Results")
        print("-" * 25)
        
        for test in suite.test_reports:
            status_icon = {
                "pass": "✅",
                "fail": "❌", 
                "skip": "⏭️",
                "error": "⚠️"
            }[test.result.value]
            
            print(f"{status_icon} {test.name} ({test.execution_time:.2f}s)")
            
            if test.result.value == "fail" or test.result.value == "error":
                if test.error_message:
                    print(f"   Error: {test.error_message}")
                if test.details:
                    print(f"   Details: {json.dumps(test.details, indent=6)}")
    
    # Generate reports
    print("\n📄 Generating Reports...")
    
    # Generate markdown report
    report_content = security_tester.generate_report(suite)
    report_file = Path(f"sandbox_security_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md")
    
    with open(report_file, 'w') as f:
        f.write(report_content)
    
    print(f"✅ Markdown report saved: {report_file}")
    
    # Generate JSON report
    json_file = report_file.with_suffix('.json')
    
    with open(json_file, 'w') as f:
        json.dump({
            "suite_id": suite.suite_id,
            "timestamp": suite.start_time.isoformat(),
            "overall_status": suite.overall_status.value,
            "security_score": suite.security_score,
            "compliance_status": suite.compliance_status,
            "test_results": [
                {
                    "test_id": test.test_id,
                    "name": test.name,
                    "result": test.result.value,
                    "severity": test.severity.value,
                    "execution_time": test.execution_time,
                    "details": test.details,
                    "error_message": test.error_message
                }
                for test in suite.test_reports
            ]
        }, f, indent=2)
    
    print(f"✅ JSON report saved: {json_file}")
    
    # Exit with appropriate code
    if suite.overall_status.value == "pass":
        print("\n🎉 All security tests passed!")
        return 0
    else:
        print("\n⚠️ Security tests failed! Please review the report.")
        return 1


def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        description="PhishNet Sandbox Security Validation Tool"
    )
    
    parser.add_argument(
        "--test-type",
        choices=["all", "network", "container", "ip-leak", "acceptance"],
        default="all",
        help="Type of security tests to run"
    )
    
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Show detailed test results"
    )
    
    parser.add_argument(
        "--config",
        type=Path,
        help="Path to security test configuration file"
    )
    
    args = parser.parse_args()
    
    # Run tests
    try:
        exit_code = asyncio.run(run_security_tests(args.test_type, args.verbose))
        sys.exit(exit_code)
    except KeyboardInterrupt:
        print("\n⏹️ Security tests interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Security tests failed with error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()