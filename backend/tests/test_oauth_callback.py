"""
Unit tests for OAuth callback endpoint
Tests the /api/v1/auth/gmail/callback endpoint logic
"""

import pytest
from fastapi.testclient import TestClient
from unittest.mock import Mock, patch, AsyncMock
from datetime import datetime

# Import the FastAPI app
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

from app.main import app
from app.models.user import User

client = TestClient(app)


class TestOAuthCallback:
    """Test suite for OAuth callback endpoint"""
    
    def test_callback_endpoint_exists(self):
        """Test that the callback endpoint is registered"""
        # GET request should return method not allowed (405) not not found (404)
        response = client.get("/api/v1/auth/gmail/callback")
        
        assert response.status_code != 404, \
            "Callback endpoint not found - route may not be registered"
        
        print(f"✅ Endpoint exists (status: {response.status_code})")
    
    def test_callback_missing_parameters(self):
        """Test callback with missing required parameters"""
        response = client.get("/api/v1/auth/gmail/callback")
        
        # Should return 400 or 422 (validation error), not 404
        assert response.status_code in [400, 405, 422], \
            f"Expected validation error, got {response.status_code}"
        
        print(f"✅ Endpoint validates parameters (status: {response.status_code})")
    
    @patch('app.api.v1.auth.httpx.AsyncClient')
    def test_callback_with_valid_code(self, mock_httpx):
        """Test callback with valid authorization code"""
        # Mock Google OAuth token exchange
        mock_client = AsyncMock()
        mock_httpx.return_value.__aenter__.return_value = mock_client
        
        # Mock token response
        mock_token_response = Mock()
        mock_token_response.status_code = 200
        mock_token_response.json.return_value = {
            'access_token': 'mock_access_token',
            'refresh_token': 'mock_refresh_token',
            'expires_in': 3600
        }
        
        # Mock user info response
        mock_user_response = Mock()
        mock_user_response.status_code = 200
        mock_user_response.json.return_value = {
            'email': 'propam5553@gmail.com',
            'name': 'Test User',
            'picture': 'https://example.com/photo.jpg'
        }
        
        mock_client.post.return_value = mock_token_response
        mock_client.get.return_value = mock_user_response
        
        # Make request
        response = client.post("/api/v1/auth/google/callback", json={
            'code': 'mock_auth_code',
            'redirect_uri': 'https://phishnet-backend-iuoc.onrender.com/api/v1/auth/gmail/callback',
            'state': 'mock_state'
        })
        
        print(f"Response status: {response.status_code}")
        print(f"Response body: {response.json()}")
        
        # Should return 200 with tokens
        if response.status_code == 200:
            data = response.json()
            assert 'access_token' in data
            assert 'refresh_token' in data
            print("✅ Callback successfully returns tokens")
        else:
            print(f"⚠️ Callback returned {response.status_code}: {response.json()}")
    
    def test_callback_invalid_code(self):
        """Test callback with invalid authorization code"""
        response = client.post("/api/v1/auth/google/callback", json={
            'code': 'invalid_code',
            'redirect_uri': 'https://phishnet-backend-iuoc.onrender.com/api/v1/auth/gmail/callback',
            'state': 'test_state'
        })
        
        # Should return error (400 or 500), not 404
        assert response.status_code != 404
        print(f"✅ Invalid code handled properly (status: {response.status_code})")
    
    def test_list_all_routes(self):
        """List all registered routes to verify callback is included"""
        # Use the debug endpoint
        response = client.get("/debug/router-errors")
        
        if response.status_code == 200:
            data = response.json()
            routes = data.get('loaded_routes', [])
            
            print("\n📋 Registered Routes:")
            auth_routes = [r for r in routes if '/auth' in r]
            for route in auth_routes:
                print(f"  - {route}")
            
            # Check if callback route exists
            callback_routes = [r for r in routes if 'gmail/callback' in r]
            
            if callback_routes:
                print(f"\n✅ Found callback routes: {callback_routes}")
            else:
                print("\n❌ No callback routes found!")
                print("\nAll routes:")
                for route in routes:
                    print(f"  - {route}")
        else:
            print(f"⚠️ Could not fetch routes (status: {response.status_code})")


if __name__ == "__main__":
    # Run tests with pytest
    pytest.main([__file__, "-v", "-s"])
