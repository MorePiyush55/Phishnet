#!/usr/bin/env python3
"""Comprehensive endpoint checker for PhishNet API."""

import os
import sys
import json
from typing import List, Dict, Any

def list_all_endpoints():
    """List all available endpoints in the FastAPI app."""
    try:
        print("🔍 Loading PhishNet application...")
        
        # Set minimal environment variables for startup
        os.environ.setdefault('MONGODB_URL', 'mongodb://localhost:27017/phishnet_test')
        os.environ.setdefault('JWT_SECRET_KEY', 'test-secret-key-for-startup')
        os.environ.setdefault('GMAIL_CLIENT_ID', 'test-client-id')
        os.environ.setdefault('GMAIL_CLIENT_SECRET', 'test-client-secret')
        
        # Import the app
        from app.main import app
        print("✅ App imported successfully!")
        
        # Get all routes
        routes = []
        for route in app.routes:
            if hasattr(route, 'path') and hasattr(route, 'methods'):
                route_info = {
                    'path': route.path,
                    'methods': list(route.methods) if route.methods else ['GET'],
                    'name': getattr(route, 'name', 'unnamed'),
                }
                routes.append(route_info)
        
        # Group routes by category
        categories = {
            'OAuth & Authentication': [],
            'Health & Status': [],
            'Email Analysis': [],
            'API Core': [],
            'Other': []
        }
        
        for route in routes:
            path = route['path'].lower()
            if any(keyword in path for keyword in ['oauth', 'auth', 'login', 'token']):
                categories['OAuth & Authentication'].append(route)
            elif any(keyword in path for keyword in ['health', 'status', 'ping', 'ready']):
                categories['Health & Status'].append(route)
            elif any(keyword in path for keyword in ['email', 'analysis', 'scan', 'gmail']):
                categories['Email Analysis'].append(route)
            elif any(keyword in path for keyword in ['/api/', '/v1/', '/test/']):
                categories['API Core'].append(route)
            else:
                categories['Other'].append(route)
        
        # Print results
        print(f"\n📊 Found {len(routes)} total endpoints\n")
        
        for category, category_routes in categories.items():
            if category_routes:
                print(f"🏷️  {category} ({len(category_routes)} endpoints):")
                for route in sorted(category_routes, key=lambda x: x['path']):
                    methods_str = ', '.join(sorted(route['methods']))
                    print(f"   {methods_str:10} {route['path']}")
                print()
        
        # Specific OAuth endpoints check
        oauth_endpoints = [r for r in routes if 'oauth' in r['path'].lower() or 'auth' in r['path'].lower()]
        print(f"🔐 OAuth Endpoints Summary ({len(oauth_endpoints)} found):")
        for endpoint in sorted(oauth_endpoints, key=lambda x: x['path']):
            methods_str = ', '.join(sorted(endpoint['methods']))
            print(f"   {methods_str:10} {endpoint['path']}")
        
        # Check for specific endpoints we need
        required_endpoints = [
            '/api/rest/auth/google',
            '/api/test/oauth',
            '/api/v1/auth/google',
            '/health'
        ]
        
        print(f"\n🎯 Required Endpoint Status:")
        for required in required_endpoints:
            found = any(route['path'] == required for route in routes)
            status = "✅ Found" if found else "❌ Missing"
            print(f"   {status:10} {required}")
            
        return True
        
    except Exception as e:
        print(f"❌ Failed to load app: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    success = list_all_endpoints()
    sys.exit(0 if success else 1)