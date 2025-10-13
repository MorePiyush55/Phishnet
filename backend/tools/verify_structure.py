#!/usr/bin/env python3
"""
Project Structure Verification Script
Checks that the reorganized PhishNet project structure is correctly set up.
"""

import os
import sys
from pathlib import Path

def check_path_exists(path, description):
    """Check if a path exists and print the result."""
    if Path(path).exists():
        print(f"✅ {description}: {path}")
        return True
    else:
        print(f"❌ {description}: {path} - NOT FOUND")
        return False

def main():
    print("🔍 PhishNet Project Structure Verification (Cleaned & Organized)")
    print("=" * 65)
    
    # Get project root (one level up from tools)
    script_dir = Path(__file__).parent
    project_root = script_dir.parent
    
    print(f"📁 Project Root: {project_root}")
    print()
    
    # Check main directories
    print("📂 Main Directories:")
    checks = []
    checks.append(check_path_exists(project_root / "backend", "Backend Directory"))
    checks.append(check_path_exists(project_root / "frontend", "Frontend Directory")) 
    checks.append(check_path_exists(project_root / "docs", "Documentation Directory"))
    checks.append(check_path_exists(project_root / "deployment", "Deployment Directory"))
    checks.append(check_path_exists(project_root / "tools", "Tools Directory"))
    print()
    
    # Check that unnecessary files are removed
    print("🧹 Cleanup Verification:")
    cleanup_items = [
        ("__pycache__", "Root Python Cache (should be removed)"),
        (".pytest_cache", "Pytest Cache (should be removed)"),
        (".coverage", "Coverage File (should be removed)"),
        ("phishnet_env", "Virtual Environment (should be removed)"),
        ("sandbox", "Sandbox Directory (should be removed)")
    ]
    
    for item, description in cleanup_items:
        if not Path(project_root / item).exists():
            print(f"✅ {description}: REMOVED")
            checks.append(True)
        else:
            print(f"❌ {description}: STILL EXISTS")
            checks.append(False)
    print()
    
    # Check organized structure
    print("🗂️ Organized Structure:")
    checks.append(check_path_exists(project_root / "deployment" / "docker-compose.yml", "Docker Compose in Deployment"))
    checks.append(check_path_exists(project_root / "deployment" / "Dockerfile", "Dockerfile in Deployment"))
    checks.append(check_path_exists(project_root / "tools" / "Makefile", "Makefile in Tools"))
    checks.append(check_path_exists(project_root / "tools" / "scripts", "Scripts in Tools"))
    print()
    
    # Check backend structure
    print("🐍 Backend Structure:")
    backend_path = project_root / "backend"
    checks.append(check_path_exists(backend_path / "app", "Backend App Directory"))
    checks.append(check_path_exists(backend_path / "app" / "main.py", "Backend Main File"))
    checks.append(check_path_exists(backend_path / "requirements.txt", "Backend Requirements"))
    checks.append(check_path_exists(backend_path / "pyproject.toml", "Backend Project Config"))
    checks.append(check_path_exists(backend_path / "tests", "Backend Tests"))
    checks.append(check_path_exists(backend_path / "alembic", "Backend Migrations"))
    print()
    
    # Check backend app modules
    print("🔧 Backend App Modules:")
    app_path = backend_path / "app"
    modules = ["api", "auth", "analyzers", "config", "core", "db", "models", "services"]
    for module in modules:
        checks.append(check_path_exists(app_path / module, f"Backend {module.title()} Module"))
    print()
    
    # Check frontend structure
    print("⚛️ Frontend Structure:")
    frontend_path = project_root / "frontend"
    checks.append(check_path_exists(frontend_path / "package.json", "Frontend Package Config"))
    checks.append(check_path_exists(frontend_path / "vite.config.ts", "Frontend Vite Config"))
    checks.append(check_path_exists(frontend_path / "src", "Frontend Source Directory"))
    checks.append(check_path_exists(frontend_path / "components", "Frontend Components"))
    checks.append(check_path_exists(frontend_path / "index.html", "Frontend Entry Point"))
    print()
    
    # Check configuration files
    print("⚙️ Configuration Files:")
    checks.append(check_path_exists(project_root / "docker-compose.yml", "Docker Compose"))
    checks.append(check_path_exists(project_root / "Dockerfile", "Dockerfile"))
    checks.append(check_path_exists(project_root / "Makefile", "Makefile"))
    checks.append(check_path_exists(project_root / "PROJECT_STRUCTURE.md", "Project Structure Doc"))
    print()
    
    # Summary
    total_checks = len(checks)
    passed_checks = sum(checks)
    
    print("📊 Summary:")
    print(f"Total Checks: {total_checks}")
    print(f"Passed: {passed_checks}")
    print(f"Failed: {total_checks - passed_checks}")
    
    if passed_checks == total_checks:
        print("\n🎉 All checks passed! Project structure is properly organized.")
        return 0
    else:
        print(f"\n⚠️ {total_checks - passed_checks} checks failed. Some files may be missing.")
        return 1

if __name__ == "__main__":
    sys.exit(main())