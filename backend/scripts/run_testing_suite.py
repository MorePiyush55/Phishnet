#!/usr/bin/env python3
"""
PhishNet Testing Suite CLI Runner
===================================
Run the full testing pipeline from the command line.

Usage:
    python run_testing_suite.py --verbose
    python run_testing_suite.py --ci-mode --commit abc123
    python run_testing_suite.py --method grid --iterations 100
"""

import argparse
import json
import sys
import os

# Ensure UTF-8 output on Windows consoles
os.environ.setdefault("PYTHONIOENCODING", "utf-8")

# Ensure backend root is on sys.path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app.testing.phishnet_test_orchestrator import (
    OrchestratorConfig,
    PhishNetTestOrchestrator,
)


def main():
    parser = argparse.ArgumentParser(
        description="PhishNet Ultimate Testing Suite",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  Full pipeline with verbose output:
    python run_testing_suite.py --verbose

  CI gate mode (exits 0/1 for pass/fail):
    python run_testing_suite.py --ci-mode --commit $(git rev-parse HEAD)

  Grid search optimization:
    python run_testing_suite.py --method grid --grid-step 10

  Quick benchmark (skip optimization):
    python run_testing_suite.py --skip-optimization --verbose
        """,
    )

    parser.add_argument(
        "--method",
        choices=["bayesian", "grid", "differential_evolution"],
        default="bayesian",
        help="Weight optimization method (default: bayesian)",
    )
    parser.add_argument(
        "--iterations",
        type=int,
        default=50,
        help="Number of optimization iterations (default: 50)",
    )
    parser.add_argument(
        "--grid-step",
        type=int,
        default=5,
        help="Grid search step size (default: 5)",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Print detailed output",
    )
    parser.add_argument(
        "--ci-mode",
        action="store_true",
        help="Run as CI gate (exit 0=pass, 1=fail)",
    )
    parser.add_argument(
        "--commit",
        type=str,
        default="",
        help="Git commit hash",
    )
    parser.add_argument(
        "--version",
        type=str,
        default="",
        help="Application version string",
    )
    parser.add_argument(
        "--skip-adversarial",
        action="store_true",
        help="Skip adversarial testing",
    )
    parser.add_argument(
        "--skip-optimization",
        action="store_true",
        help="Skip weight optimization (evaluate only)",
    )
    parser.add_argument(
        "--output-dir",
        type=str,
        default="backend/app/testing/reports",
        help="Report output directory",
    )
    parser.add_argument(
        "--dataset",
        type=str,
        default=None,
        help="Path to custom dataset JSON file",
    )

    args = parser.parse_args()

    # Build config from CLI args
    config = OrchestratorConfig(
        dataset_path=args.dataset,
        use_builtin_dataset=args.dataset is None,
        optimization_method=args.method,
        optimization_iterations=args.iterations,
        grid_step=args.grid_step,
        include_adversarial=not args.skip_adversarial,
        report_output_dir=args.output_dir,
    )

    orchestrator = PhishNetTestOrchestrator(config=config)

    if args.ci_mode:
        # CI gate mode — simplified flow
        print("=" * 60)
        print("PHISHNET CI GATE — REGRESSION CHECK")
        print("=" * 60)

        result = orchestrator.run(
            commit_hash=args.commit,
            version=args.version,
            verbose=args.verbose,
        )

        if result.safe_to_deploy:
            print(f"\n[PASS] CI GATE: PASSED (F1={result.initial_metrics.get('overall', {}).get('f1_score', 'N/A') if result.initial_metrics else 'N/A'})")
            sys.exit(0)
        else:
            print(f"\n[FAIL] CI GATE: BLOCKED")
            for blocker in result.deployment_blockers:
                print(f"   [!] {blocker}")
            sys.exit(1)
    else:
        # Full pipeline run
        print("=" * 60)
        print("PHISHNET ULTIMATE TESTING SUITE")
        print("=" * 60)

        result = orchestrator.run(
            commit_hash=args.commit,
            version=args.version,
            verbose=args.verbose,
        )

        # Summary
        print("\n" + "=" * 60)
        print("FINAL SUMMARY")
        print("=" * 60)
        print(f"  Success:        {result.success}")
        print(f"  Safe to Deploy: {result.safe_to_deploy}")
        print(f"  Duration:       {result.duration_seconds:.1f}s")

        if result.initial_metrics:
            overall = result.initial_metrics.get("overall", {})
            print(f"  F1 Score:       {overall.get('f1_score', 'N/A')}")
            print(f"  Recall:         {overall.get('recall', 'N/A')}")
            print(f"  Precision:      {overall.get('precision', 'N/A')}")

        if result.optimization_result:
            print(f"  Optimized F1:   {result.optimization_result.get('best_f1', 'N/A')}")

        if result.deployment_blockers:
            print("\n  [!] Deployment Blockers:")
            for b in result.deployment_blockers:
                print(f"     - {b}")

        if result.report_paths:
            print("\n  Reports:")
            for p in result.report_paths:
                print(f"     - {p}")

        print("=" * 60)

        sys.exit(0 if result.success else 1)


if __name__ == "__main__":
    main()
