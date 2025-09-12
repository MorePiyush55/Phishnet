#!/usr/bin/env python3
"""
PhishNet CLI - Command Line Interface

Unified CLI for all PhishNet operations including setup, testing, demos, and administration.
This replaces scattered if __name__ == '__main__' blocks throughout the codebase.
"""

import argparse
import asyncio
import sys
from pathlib import Path
from typing import Optional

# Add project root to path for imports
project_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(project_root))

# Suppress warnings for cleaner output
import warnings
warnings.filterwarnings("ignore", category=UserWarning)


def setup_database_command(args):
    """Initialize database with schema and sample data."""
    from scripts.init_db import main as init_db_main
    print("🗄️  Initializing database...")
    return init_db_main()


def setup_backbone_command(args):
    """Setup Phase 1: Core backbone infrastructure."""
    from scripts.phase1_backbone import setup_backbone
    print("🏗️  Setting up Phase 1 backbone...")
    return setup_backbone()


def setup_emails_command(args):
    """Setup Phase 2: Email processing domain."""
    from scripts.phase2_emails import main as phase2_main
    print("📧 Setting up Phase 2 emails...")
    return phase2_main()


def setup_links_command(args):
    """Setup Phase 3: Link analysis domain.""" 
    from scripts.phase3_links import main as phase3_main
    print("🔗 Setting up Phase 3 links...")
    return phase3_main()


async def demo_sandbox(args):
    """Run sandbox analysis demo."""
    from app.core.sandbox import example_usage
    print("🔬 Running sandbox analysis demo...")
    await example_usage()


def demo_security(args):
    """Run enhanced security demo."""
    from app.core.enhanced_security import example_enhanced_security_usage
    print("🔐 Running enhanced security demo...")
    example_enhanced_security_usage()


def run_tests_command(args):
    """Run comprehensive test suite."""
    from test.run_tests import main as run_tests_main
    print("🧪 Running test suite...")
    
    # Convert args to namespace for test runner
    test_args = argparse.Namespace(
        unit=args.unit,
        integration=args.integration,
        api=args.api,
        lint=args.lint,
        coverage=args.coverage,
        security=args.security,
        performance=args.performance,
        cleanup=args.cleanup,
        ci=args.ci,
        verbose=args.verbose
    )
    return run_tests_main(test_args)


def validate_config_command(args):
    """Validate application configuration."""
    from src.common.config_validator import validate_configuration
    print("⚙️  Validating configuration...")
    
    is_valid, report = validate_configuration(print_report=True, raise_on_error=False)
    
    if is_valid:
        print("\n✅ Configuration is valid and ready for use!")
        return True
    else:
        print("\n❌ Configuration has errors that need to be fixed.")
        return False


async def health_check_command(args):
    """Run comprehensive health checks."""
    from app.health.service import get_health_service
    
    print("🏥 Running comprehensive health checks...")
    
    service = get_health_service()
    report = await service.check_all(parallel=True, include_details=True)
    
    # Print formatted report
    service.print_health_report(report, show_details=True)
    
    # Return success based on overall status
    overall_status = report.get('overall_status', 'unknown')
    return overall_status in ['healthy', 'degraded']


async def start_server_command(args):
    """Start the PhishNet API server."""
    import uvicorn
    from app.main import app
    
    print(f"🚀 Starting PhishNet server on {args.host}:{args.port}")
    config = uvicorn.Config(
        app, 
        host=args.host, 
        port=args.port, 
        reload=args.reload,
        log_level=args.log_level
    )
    server = uvicorn.Server(config)
    await server.serve()


def create_parser():
    """Create the main argument parser."""
    parser = argparse.ArgumentParser(
        description="PhishNet CLI - Unified command line interface",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s setup database                 # Initialize database
  %(prog)s setup backbone                 # Setup core infrastructure
  %(prog)s demo sandbox                   # Run sandbox demo
  %(prog)s test --unit --coverage         # Run unit tests with coverage
  %(prog)s server --reload                # Start development server
  %(prog)s health                         # Run health checks
        """
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Setup commands
    setup_parser = subparsers.add_parser('setup', help='Setup and initialization')
    setup_subparsers = setup_parser.add_subparsers(dest='setup_command')
    
    setup_subparsers.add_parser('database', help='Initialize database')
    setup_subparsers.add_parser('backbone', help='Setup Phase 1 backbone')
    setup_subparsers.add_parser('emails', help='Setup Phase 2 emails')
    setup_subparsers.add_parser('links', help='Setup Phase 3 links')
    
    # Demo commands
    demo_parser = subparsers.add_parser('demo', help='Run demonstrations')
    demo_subparsers = demo_parser.add_subparsers(dest='demo_command')
    
    demo_subparsers.add_parser('sandbox', help='Run sandbox analysis demo')
    demo_subparsers.add_parser('security', help='Run security features demo')
    
    # Test commands
    test_parser = subparsers.add_parser('test', help='Run tests')
    test_parser.add_argument('--unit', action='store_true', help='Run unit tests')
    test_parser.add_argument('--integration', action='store_true', help='Run integration tests')
    test_parser.add_argument('--api', action='store_true', help='Run API tests')
    test_parser.add_argument('--lint', action='store_true', help='Run linting')
    test_parser.add_argument('--coverage', action='store_true', help='Generate coverage report')
    test_parser.add_argument('--security', action='store_true', help='Run security scan')
    test_parser.add_argument('--performance', action='store_true', help='Run performance tests')
    test_parser.add_argument('--cleanup', action='store_true', help='Cleanup test artifacts')
    test_parser.add_argument('--ci', action='store_true', help='Run all tests for CI')
    test_parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')
    
    # Server command
    server_parser = subparsers.add_parser('server', help='Start API server')
    server_parser.add_argument('--host', default='localhost', help='Host to bind to')
    server_parser.add_argument('--port', type=int, default=8000, help='Port to bind to')
    server_parser.add_argument('--reload', action='store_true', help='Enable auto-reload')
    server_parser.add_argument('--log-level', default='info', choices=['debug', 'info', 'warning', 'error'])
    
    # Config and health commands
    subparsers.add_parser('config', help='Validate configuration')
    subparsers.add_parser('health', help='Run health checks')
    
    return parser


async def async_main():
    """Async main function for commands that need async support."""
    parser = create_parser()
    args = parser.parse_args()
    
    success = True
    
    try:
        if args.command == 'setup':
            if args.setup_command == 'database':
                success = setup_database_command(args)
            elif args.setup_command == 'backbone':
                success = setup_backbone_command(args)
            elif args.setup_command == 'emails':
                success = setup_emails_command(args)
            elif args.setup_command == 'links':
                success = setup_links_command(args)
            else:
                parser.parse_args(['setup', '--help'])
                
        elif args.command == 'demo':
            if args.demo_command == 'sandbox':
                await demo_sandbox(args)
            elif args.demo_command == 'security':
                demo_security(args)
            else:
                parser.parse_args(['demo', '--help'])
                
        elif args.command == 'test':
            success = run_tests_command(args)
            
        elif args.command == 'server':
            await start_server_command(args)
            
        elif args.command == 'config':
            success = validate_config_command(args)
            
        elif args.command == 'health':
            success = await health_check_command(args)
            
        else:
            parser.print_help()
            
    except KeyboardInterrupt:
        print("\n👋 Interrupted by user")
        success = False
    except Exception as e:
        print(f"\n❌ Error: {e}")
        success = False
    
    return success


def main():
    """Main entry point."""
    success = asyncio.run(async_main())
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
