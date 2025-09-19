#!/usr/bin/env python3
"""
PhishNet MongoDB Configuration Checker
"""

import os
import sys
from pathlib import Path

# Add the backend directory to Python path
backend_dir = Path(__file__).parent
sys.path.insert(0, str(backend_dir))

try:
    from app.config.settings import settings
    
    print("🔧 PhishNet MongoDB Configuration Check")
    print("=" * 50)
    
    # Check MongoDB configuration
    mongodb_uri = settings.get_mongodb_uri()
    has_password = bool(settings.MONGODB_PASSWORD)
    
    print(f"✅ MongoDB URI configured: {bool(mongodb_uri)}")
    print(f"🔑 MongoDB Password set: {has_password}")
    print(f"🗄️  MongoDB Database: {settings.MONGODB_DATABASE}")
    
    if mongodb_uri and has_password:
        print("\n✅ MongoDB configuration looks complete!")
        print("🚀 You can now start the application with: python main.py")
    elif mongodb_uri and not has_password:
        print("\n⚠️  MongoDB URI is configured but password is missing")
        print("📝 Please set MONGODB_PASSWORD in your .env file")
        print("💡 The password should match your MongoDB Atlas cluster password")
    else:
        print("\n❌ MongoDB configuration is incomplete")
        print("📝 Please configure MONGODB_URI and MONGODB_PASSWORD in your .env file")
    
    print("\n📋 Current Configuration:")
    if mongodb_uri:
        # Hide password in output for security
        safe_uri = mongodb_uri.replace(settings.MONGODB_PASSWORD or "password", "***") if settings.MONGODB_PASSWORD else mongodb_uri
        print(f"   URI: {safe_uri}")
    else:
        print("   URI: Not configured")
    
    print(f"   Database: {settings.MONGODB_DATABASE}")
    print(f"   Password: {'Set' if has_password else 'Not set'}")

except ImportError as e:
    print(f"❌ Error importing settings: {e}")
    print("Make sure you're running this from the backend directory")
except Exception as e:
    print(f"❌ Configuration error: {e}")