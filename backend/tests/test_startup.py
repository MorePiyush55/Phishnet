#!/usr/bin/env python3
"""Test script to verify the app can start properly for Render deployment."""

import os
import sys

def test_app_startup():
    """Test if the app can be imported and started."""
    try:
        print("Testing app startup...")
        
        # Set minimal environment variables for startup
        os.environ.setdefault('MONGODB_URL', 'mongodb://localhost:27017/phishnet_test')
        os.environ.setdefault('JWT_SECRET_KEY', 'test-secret-key-for-startup')
        os.environ.setdefault('GMAIL_CLIENT_ID', 'test-client-id')
        os.environ.setdefault('GMAIL_CLIENT_SECRET', 'test-client-secret')
        
        # Try to import the app
        from app.main import app
        print("✅ App imported successfully!")
        
        # Check if the app has the necessary routes
        routes = [route.path for route in app.routes]
        print(f"✅ App has {len(routes)} routes")
        
        # Check for OAuth routes specifically
        oauth_routes = [route for route in routes if 'oauth' in route or 'auth' in route]
        print(f"✅ Found {len(oauth_routes)} OAuth-related routes")
        
        return True
        
    except Exception as e:
        print(f"❌ App startup failed: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    success = test_app_startup()
    sys.exit(0 if success else 1)