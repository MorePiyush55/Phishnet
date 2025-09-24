#!/usr/bin/env python3
"""
Test Runner for Link Redirect Analysis

Runs comprehensive tests for the link redirect analysis system
with proper configuration and reporting.
"""

import sys
import subprocess
import argparse
from pathlib import Path


def run_tests(test_type="all", verbose=False, coverage=False, html_report=False):
    """Run tests with specified options."""
    
    # Base test directory
    test_dir = Path(__file__).parent
    
    # Test command
    cmd = ["python", "-m", "pytest"]
    
    # Test selection
    if test_type == "unit":
        cmd.extend([str(test_dir / "test_link_redirect_analysis.py::TestLinkRedirectAnalyzer")])
    elif test_type == "api":
        cmd.extend([str(test_dir / "test_link_redirect_analysis.py::TestLinkAnalysisAPI")])
    elif test_type == "integration":
        cmd.extend(["-m", "integration"])
    elif test_type == "performance":
        cmd.extend(["-m", "performance"])
    elif test_type == "all":
        cmd.extend([str(test_dir / "test_link_redirect_analysis.py")])
    
    # Verbosity
    if verbose:
        cmd.append("-v")
    else:
        cmd.append("-q")
    
    # Coverage
    if coverage:
        cmd.extend([
            "--cov=app.services.link_redirect_analyzer",
            "--cov=app.api.link_analysis",
            "--cov-report=term-missing"
        ])
        
        if html_report:
            cmd.extend(["--cov-report=html:htmlcov"])
    
    # Additional options
    cmd.extend([
        "--tb=short",  # Short traceback format
        "--strict-markers",  # Strict marker checking
        "-x",  # Stop on first failure
    ])
    
    print(f"Running command: {' '.join(cmd)}")
    
    try:
        result = subprocess.run(cmd, cwd=test_dir.parent, capture_output=False)
        return result.returncode
    except KeyboardInterrupt:
        print("\nTests interrupted by user")
        return 130
    except Exception as e:
        print(f"Error running tests: {e}")
        return 1


def main():
    """Main test runner entry point."""
    parser = argparse.ArgumentParser(description="Run Link Redirect Analysis tests")
    
    parser.add_argument(
        "--type", "-t",
        choices=["all", "unit", "api", "integration", "performance"],
        default="all",
        help="Type of tests to run (default: all)"
    )
    
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose output"
    )
    
    parser.add_argument(
        "--coverage", "-c",
        action="store_true",
        help="Enable coverage reporting"
    )
    
    parser.add_argument(
        "--html-report",
        action="store_true",
        help="Generate HTML coverage report"
    )
    
    parser.add_argument(
        "--quick", "-q",
        action="store_true",
        help="Run quick tests only (skip integration and performance)"
    )
    
    args = parser.parse_args()
    
    if args.quick and args.type == "all":
        args.type = "unit"
    
    # Run tests
    exit_code = run_tests(
        test_type=args.type,
        verbose=args.verbose,
        coverage=args.coverage,
        html_report=args.html_report
    )
    
    # Print summary
    if exit_code == 0:
        print("\n✅ All tests passed!")
        if args.coverage and args.html_report:
            print("📊 Coverage report generated in htmlcov/index.html")
    else:
        print(f"\n❌ Tests failed with exit code {exit_code}")
    
    sys.exit(exit_code)


if __name__ == "__main__":
    main()