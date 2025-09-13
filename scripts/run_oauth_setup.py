#!/usr/bin/env python3
"""
PhishNet Gmail OAuth Setup & Test Runner
Complete setup automation and testing
"""

import subprocess
import sys
import os
import argparse
import time
import requests
from pathlib import Path

def run_command(command, description, check=True):
    """Run a shell command with description."""
    print(f"🔄 {description}")
    try:
        result = subprocess.run(command, shell=True, check=check, capture_output=True, text=True)
        if result.returncode == 0:
            print(f"✅ {description} - SUCCESS")
            if result.stdout.strip():
                print(f"   Output: {result.stdout.strip()}")
        else:
            print(f"❌ {description} - FAILED")
            if result.stderr.strip():
                print(f"   Error: {result.stderr.strip()}")
        return result.returncode == 0
    except Exception as e:
        print(f"❌ {description} - ERROR: {e}")
        return False

def check_prerequisites():
    """Check if all prerequisites are installed."""
    print("🔍 Checking prerequisites...")
    
    checks = [
        ("python --version", "Python installation"),
        ("pip --version", "Pip package manager"),
        ("gcloud --version", "Google Cloud CLI"),
        ("node --version", "Node.js (for frontend)"),
        ("npm --version", "NPM package manager")
    ]
    
    all_good = True
    for command, description in checks:
        if not run_command(command, f"Checking {description}", check=False):
            all_good = False
    
    return all_good

def setup_backend_dependencies():
    """Install backend dependencies."""
    print("\n📦 Setting up backend dependencies...")
    
    commands = [
        ("pip install -r requirements.txt", "Installing main requirements"),
        ("pip install -r requirements-oauth.txt", "Installing OAuth requirements"),
        ("alembic upgrade head", "Running database migrations")
    ]
    
    for command, description in commands:
        if not run_command(command, description):
            return False
    
    return True

def setup_frontend_dependencies():
    """Install frontend dependencies."""
    print("\n🎨 Setting up frontend dependencies...")
    
    os.chdir("frontend")
    
    commands = [
        ("npm install", "Installing frontend packages"),
        ("npm run build", "Building frontend")
    ]
    
    for command, description in commands:
        if not run_command(command, description):
            os.chdir("..")
            return False
    
    os.chdir("..")
    return True

def run_google_cloud_setup(project_id, domain, backend_url):
    """Run Google Cloud setup script."""
    print(f"\n☁️ Setting up Google Cloud resources...")
    
    if os.name == 'nt':  # Windows
        command = f'powershell -ExecutionPolicy Bypass -File scripts/Setup-GoogleCloud.ps1 -ProjectId "{project_id}" -Domain "{domain}" -BackendUrl "{backend_url}"'
    else:  # Linux/Mac
        command = f'python scripts/setup_google_cloud.py --project-id "{project_id}" --domain "{domain}" --backend-url "{backend_url}"'
    
    return run_command(command, "Setting up Google Cloud resources")

def test_backend_health():
    """Test backend health endpoints."""
    print("\n🏥 Testing backend health...")
    
    # Check if backend is running
    try:
        response = requests.get("http://localhost:8000/health", timeout=5)
        if response.status_code == 200:
            print("✅ Backend health check - SUCCESS")
            return True
        else:
            print(f"❌ Backend health check - FAILED (Status: {response.status_code})")
            return False
    except requests.exceptions.RequestException as e:
        print(f"❌ Backend health check - ERROR: {e}")
        print("   Make sure backend is running on http://localhost:8000")
        return False

def test_oauth_endpoints():
    """Test OAuth endpoints."""
    print("\n🔐 Testing OAuth endpoints...")
    
    endpoints = [
        "http://localhost:8000/api/v1/auth/gmail/health",
        "http://localhost:8000/api/v1/auth/gmail/status"
    ]
    
    for endpoint in endpoints:
        try:
            response = requests.get(endpoint, timeout=5)
            if response.status_code in [200, 401]:  # 401 is OK for protected endpoints
                print(f"✅ {endpoint} - ACCESSIBLE")
            else:
                print(f"❌ {endpoint} - FAILED (Status: {response.status_code})")
                return False
        except requests.exceptions.RequestException as e:
            print(f"❌ {endpoint} - ERROR: {e}")
            return False
    
    return True

def start_development_servers():
    """Start development servers."""
    print("\n🚀 Starting development servers...")
    
    # Start backend
    backend_process = subprocess.Popen(
        ["uvicorn", "app.main:app", "--reload", "--host", "0.0.0.0", "--port", "8000"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )
    
    print("✅ Backend started on http://localhost:8000")
    
    # Wait a bit for backend to start
    time.sleep(3)
    
    # Start frontend
    os.chdir("frontend")
    frontend_process = subprocess.Popen(
        ["npm", "run", "dev"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )
    os.chdir("..")
    
    print("✅ Frontend started on http://localhost:3000")
    
    return backend_process, frontend_process

def main():
    parser = argparse.ArgumentParser(description="PhishNet Gmail OAuth Setup & Test Runner")
    parser.add_argument("--project-id", help="Google Cloud Project ID")
    parser.add_argument("--domain", help="Your domain (e.g., phishnet.app)")
    parser.add_argument("--backend-url", help="Backend URL (e.g., https://api.phishnet.app)")
    parser.add_argument("--skip-gcloud", action="store_true", help="Skip Google Cloud setup")
    parser.add_argument("--skip-deps", action="store_true", help="Skip dependency installation")
    parser.add_argument("--test-only", action="store_true", help="Only run tests")
    parser.add_argument("--start-servers", action="store_true", help="Start development servers")
    
    args = parser.parse_args()
    
    print("🚀 PhishNet Gmail OAuth Setup & Test Runner")
    print("=" * 60)
    
    # Check prerequisites
    if not args.test_only and not check_prerequisites():
        print("\n❌ Prerequisites check failed. Please install missing dependencies.")
        sys.exit(1)
    
    # Install dependencies
    if not args.skip_deps and not args.test_only:
        if not setup_backend_dependencies():
            print("\n❌ Backend setup failed.")
            sys.exit(1)
        
        if not setup_frontend_dependencies():
            print("\n❌ Frontend setup failed.")
            sys.exit(1)
    
    # Google Cloud setup
    if not args.skip_gcloud and not args.test_only and args.project_id:
        if not run_google_cloud_setup(args.project_id, args.domain, args.backend_url):
            print("\n❌ Google Cloud setup failed.")
            sys.exit(1)
    
    # Run tests
    if args.test_only or args.start_servers:
        if not test_backend_health():
            print("\n❌ Backend tests failed.")
            if not args.start_servers:
                sys.exit(1)
        
        if not test_oauth_endpoints():
            print("\n❌ OAuth endpoint tests failed.")
            if not args.start_servers:
                sys.exit(1)
    
    # Start development servers
    if args.start_servers:
        try:
            backend_proc, frontend_proc = start_development_servers()
            
            print("\n🎉 Development environment ready!")
            print("Frontend: http://localhost:3000")
            print("Backend: http://localhost:8000")
            print("API Docs: http://localhost:8000/docs")
            print("\nPress Ctrl+C to stop servers...")
            
            # Wait for user interrupt
            while True:
                time.sleep(1)
                
        except KeyboardInterrupt:
            print("\n🛑 Stopping servers...")
            backend_proc.terminate()
            frontend_proc.terminate()
            print("✅ Servers stopped.")
    
    print("\n🎉 Setup complete!")
    
    if args.project_id:
        print(f"\nNext steps:")
        print(f"1. Complete OAuth consent screen: https://console.cloud.google.com/apis/credentials/consent?project={args.project_id}")
        print(f"2. Create OAuth credentials: https://console.cloud.google.com/apis/credentials?project={args.project_id}")
        print(f"3. Update .env.production with OAuth client ID and secret")
        print(f"4. Test OAuth flow in development")

if __name__ == "__main__":
    main()
