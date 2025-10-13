#!/usr/bin/env python3
"""
OAuth Client Configuration for PhishNet
Creates and configures OAuth 2.0 credentials using Google Cloud API
"""

import json
import requests
import os
from typing import Dict, Optional
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build

class OAuthClientManager:
    def __init__(self, project_id: str, domain: str, backend_url: str):
        self.project_id = project_id
        self.domain = domain
        self.backend_url = backend_url
        self.frontend_url = f"https://{domain}"
        
    def create_oauth_client(self) -> Dict:
        """Create OAuth 2.0 web application credentials"""
        
        # OAuth client configuration
        client_config = {
            "web": {
                "client_id": "",
                "client_secret": "",
                "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                "token_uri": "https://oauth2.googleapis.com/token",
                "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
                "redirect_uris": [
                    f"{self.backend_url}/api/v1/auth/gmail/callback"
                ],
                "javascript_origins": [
                    self.frontend_url
                ]
            }
        }
        
        # Create credentials using Cloud Resource Manager API
        service = build('cloudresourcemanager', 'v1')
        
        # This is a placeholder - actual OAuth client creation requires
        # using the Google Cloud Console API or manual setup
        
        print(f"""
🔧 OAuth Client Configuration Template:

Authorized Redirect URIs:
- {self.backend_url}/api/v1/auth/gmail/callback

Authorized JavaScript Origins:
- {self.frontend_url}

Required Scopes:
- https://www.googleapis.com/auth/gmail.readonly
- https://www.googleapis.com/auth/gmail.modify
- https://www.googleapis.com/auth/gmail.labels
- openid
- email
- profile

Save the client_config.json:
        """)
        
        with open("client_config.json", "w") as f:
            json.dump(client_config, f, indent=2)
        
        print("✅ OAuth client template saved to client_config.json")
        return client_config

    def test_oauth_flow(self, client_config_path: str):
        """Test OAuth flow with created credentials"""
        if not os.path.exists(client_config_path):
            print("❌ Client config file not found")
            return
        
        # Create OAuth flow for testing
        flow = Flow.from_client_secrets_file(
            client_config_path,
            scopes=[
                'https://www.googleapis.com/auth/gmail.readonly',
                'https://www.googleapis.com/auth/gmail.modify',
                'openid',
                'email',
                'profile'
            ]
        )
        
        flow.redirect_uri = f"{self.backend_url}/api/v1/auth/gmail/callback"
        
        # Generate authorization URL
        auth_url, _ = flow.authorization_url(
            access_type='offline',
            include_granted_scopes='true',
            prompt='consent'
        )
        
        print(f"🔗 Test OAuth URL: {auth_url}")

def main():
    import argparse
    
    parser = argparse.ArgumentParser(description="Configure OAuth client for PhishNet")
    parser.add_argument("--project-id", required=True, help="Google Cloud Project ID")
    parser.add_argument("--domain", required=True, help="Your domain")
    parser.add_argument("--backend-url", required=True, help="Backend URL")
    parser.add_argument("--test", action="store_true", help="Test OAuth flow")
    
    args = parser.parse_args()
    
    manager = OAuthClientManager(args.project_id, args.domain, args.backend_url)
    
    if args.test:
        manager.test_oauth_flow("client_config.json")
    else:
        manager.create_oauth_client()

if __name__ == "__main__":
    main()
