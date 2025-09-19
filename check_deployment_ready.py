#!/usr/bin/env python3
"""
Pre-deployment verification script
Checks if backend is ready for deployment
"""

import os
import sys
import requests
import json
from pathlib import Path

def check_backend_files():
    """Check if all required backend files exist"""
    print("🔍 Checking Backend Files...")
    
    backend_path = Path("backend")
    required_files = [
        "main.py",
        "requirements.txt", 
        "render.yaml",
        "Procfile",
        "app/main.py",
        "app/config/settings.py",
        "app/models/mongodb_models.py",
        "app/core/auth_simple.py",
        "app/api/health.py",
        "app/api/auth_simple.py",
        "app/api/simple_analysis.py"
    ]
    
    missing_files = []
    for file_path in required_files:
        full_path = backend_path / file_path
        if not full_path.exists():
            missing_files.append(str(file_path))
        else:
            print(f"   ✅ {file_path}")
    
    if missing_files:
        print(f"   ❌ Missing files: {missing_files}")
        return False
    
    print("   ✅ All backend files present")
    return True

def check_frontend_files():
    """Check if all required frontend files exist"""
    print("\n🔍 Checking Frontend Files...")
    
    frontend_path = Path("frontend")
    required_files = [
        "package.json",
        "vercel.json",
        ".env.production",
        "src/main.tsx",
        "vite.config.ts"
    ]
    
    missing_files = []
    for file_path in required_files:
        full_path = frontend_path / file_path
        if not full_path.exists():
            missing_files.append(str(file_path))
        else:
            print(f"   ✅ {file_path}")
    
    if missing_files:
        print(f"   ❌ Missing files: {missing_files}")
        return False
    
    print("   ✅ All frontend files present")
    return True

def check_environment_config():
    """Check environment configuration"""
    print("\n🔍 Checking Environment Configuration...")
    
    # Check backend .env
    backend_env = Path("backend/.env")
    if backend_env.exists():
        print("   ✅ Backend .env exists")
        
        # Check for MongoDB URI
        with open(backend_env, 'r') as f:
            content = f.read()
            if "MONGODB_URI" in content:
                print("   ✅ MongoDB URI configured")
            else:
                print("   ❌ MongoDB URI not found in .env")
                return False
    else:
        print("   ❌ Backend .env file missing")
        return False
    
    # Check frontend .env.production
    frontend_env = Path("frontend/.env.production")
    if frontend_env.exists():
        print("   ✅ Frontend .env.production exists")
        
        with open(frontend_env, 'r') as f:
            content = f.read()
            if "VITE_API_BASE_URL" in content:
                print("   ✅ Frontend API URL configured")
            else:
                print("   ❌ Frontend API URL not configured")
                return False
    else:
        print("   ❌ Frontend .env.production missing")
        return False
    
    return True

def check_dependencies():
    """Check if dependencies are properly specified"""
    print("\n🔍 Checking Dependencies...")
    
    # Check backend requirements.txt
    requirements_path = Path("backend/requirements.txt")
    if requirements_path.exists():
        with open(requirements_path, 'r') as f:
            requirements = f.read()
            
        essential_deps = ["fastapi", "motor", "beanie", "bcrypt", "python-jose"]
        missing_deps = []
        
        for dep in essential_deps:
            if dep not in requirements.lower():
                missing_deps.append(dep)
        
        if missing_deps:
            print(f"   ❌ Missing backend dependencies: {missing_deps}")
            return False
        else:
            print("   ✅ Backend dependencies look good")
    else:
        print("   ❌ requirements.txt not found")
        return False
    
    # Check frontend package.json
    package_json_path = Path("frontend/package.json")
    if package_json_path.exists():
        with open(package_json_path, 'r') as f:
            package_data = json.load(f)
        
        if "build" in package_data.get("scripts", {}):
            print("   ✅ Frontend build script configured")
        else:
            print("   ❌ Frontend build script missing")
            return False
    else:
        print("   ❌ Frontend package.json not found")
        return False
    
    return True

def check_api_endpoints():
    """Check if running backend has correct endpoints"""
    print("\n🔍 Checking API Endpoints (if backend is running)...")
    
    try:
        # Test basic health
        response = requests.get("http://localhost:8000/health", timeout=5)
        if response.status_code == 200:
            print("   ✅ Health endpoint working")
        else:
            print(f"   ⚠️  Health endpoint returned {response.status_code}")
    except requests.exceptions.ConnectionError:
        print("   ⚠️  Backend not running locally (this is OK for deployment)")
        return True
    except Exception as e:
        print(f"   ⚠️  Could not test endpoints: {e}")
        return True
    
    try:
        # Test auth endpoints
        response = requests.get("http://localhost:8000/api/auth/test", timeout=5)
        if response.status_code == 200:
            print("   ✅ Auth endpoints working")
        else:
            print(f"   ❌ Auth endpoints returned {response.status_code}")
    except Exception as e:
        print(f"   ⚠️  Auth endpoint test failed: {e}")
    
    return True

def main():
    """Run all deployment checks"""
    print("🚀 PhishNet Deployment Readiness Check")
    print("=" * 50)
    
    checks = [
        ("Backend Files", check_backend_files),
        ("Frontend Files", check_frontend_files), 
        ("Environment Config", check_environment_config),
        ("Dependencies", check_dependencies),
        ("API Endpoints", check_api_endpoints)
    ]
    
    all_passed = True
    
    for check_name, check_func in checks:
        try:
            result = check_func()
            if not result:
                all_passed = False
        except Exception as e:
            print(f"   ❌ {check_name} check failed: {e}")
            all_passed = False
    
    print("\n" + "=" * 50)
    if all_passed:
        print("🎉 ALL CHECKS PASSED!")
        print("✅ Your project is ready for deployment!")
        print("\nNext steps:")
        print("1. Push changes to GitHub")
        print("2. Deploy backend to Render")
        print("3. Deploy frontend to Vercel") 
        print("4. Update CORS settings with final URLs")
    else:
        print("❌ SOME CHECKS FAILED")
        print("Please fix the issues above before deploying")
        sys.exit(1)

if __name__ == "__main__":
    main()