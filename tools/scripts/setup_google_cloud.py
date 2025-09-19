#!/usr/bin/env python3
"""
Google Cloud Console Setup Script for PhishNet Gmail OAuth
Automates the creation and configuration of Google Cloud resources
"""

import json
import subprocess
import sys
import os
from typing import Dict, List, Optional
import argparse

class GoogleCloudSetup:
    def __init__(self, project_id: str, domain: str, backend_url: str):
        self.project_id = project_id
        self.domain = domain
        self.backend_url = backend_url
        self.frontend_url = f"https://{domain}"
        
    def run_gcloud_command(self, command: List[str]) -> Dict:
        """Execute gcloud command and return JSON output"""
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                check=True
            )
            return json.loads(result.stdout) if result.stdout.strip() else {}
        except subprocess.CalledProcessError as e:
            print(f"Error running command: {' '.join(command)}")
            print(f"Error: {e.stderr}")
            sys.exit(1)
        except json.JSONDecodeError:
            print(f"Non-JSON output from command: {' '.join(command)}")
            return {}

    def check_gcloud_auth(self):
        """Check if user is authenticated with gcloud"""
        try:
            result = subprocess.run(
                ["gcloud", "auth", "list", "--format=json"],
                capture_output=True,
                text=True,
                check=True
            )
            accounts = json.loads(result.stdout)
            if not accounts:
                print("❌ No authenticated gcloud accounts found.")
                print("Run: gcloud auth login")
                sys.exit(1)
            
            active_account = next((acc for acc in accounts if acc.get('status') == 'ACTIVE'), None)
            if not active_account:
                print("❌ No active gcloud account found.")
                print("Run: gcloud auth login")
                sys.exit(1)
                
            print(f"✅ Authenticated as: {active_account['account']}")
            
        except (subprocess.CalledProcessError, json.JSONDecodeError):
            print("❌ gcloud CLI not found or not properly configured.")
            print("Install gcloud CLI: https://cloud.google.com/sdk/docs/install")
            sys.exit(1)

    def create_project(self):
        """Create Google Cloud Project"""
        print(f"🔄 Creating project: {self.project_id}")
        
        # Check if project exists
        try:
            self.run_gcloud_command([
                "gcloud", "projects", "describe", self.project_id, "--format=json"
            ])
            print(f"✅ Project {self.project_id} already exists")
            return
        except:
            pass
        
        # Create project
        self.run_gcloud_command([
            "gcloud", "projects", "create", self.project_id,
            "--name", "PhishNet Gmail Integration",
            "--format=json"
        ])
        print(f"✅ Created project: {self.project_id}")
        
        # Set as active project
        subprocess.run(["gcloud", "config", "set", "project", self.project_id], check=True)

    def enable_apis(self):
        """Enable required APIs"""
        apis = [
            "gmail.googleapis.com",
            "people.googleapis.com",
            "pubsub.googleapis.com",
            "cloudbuild.googleapis.com",
            "secretmanager.googleapis.com"
        ]
        
        print("🔄 Enabling APIs...")
        for api in apis:
            print(f"  Enabling {api}")
            subprocess.run([
                "gcloud", "services", "enable", api, 
                "--project", self.project_id
            ], check=True)
        
        print("✅ All APIs enabled")

    def create_oauth_credentials(self) -> Dict:
        """Create OAuth 2.0 credentials"""
        print("🔄 Creating OAuth 2.0 credentials...")
        
        # Create OAuth consent screen first
        consent_config = {
            "applicationTitle": "PhishNet Email Security",
            "supportEmail": f"support@{self.domain}",
            "authorizedDomains": [self.domain],
            "privacyPolicyUri": f"https://{self.domain}/privacy",
            "termsOfServiceUri": f"https://{self.domain}/terms"
        }
        
        # Note: OAuth consent screen configuration requires manual setup via console
        # as gcloud doesn't support full automation of consent screen
        print(f"""
📋 Manual OAuth Consent Screen Setup Required:
1. Go to: https://console.cloud.google.com/apis/credentials/consent?project={self.project_id}
2. Configure OAuth consent screen:
   - Application name: PhishNet Email Security
   - User support email: support@{self.domain}
   - Authorized domains: {self.domain}
   - Privacy Policy: https://{self.domain}/privacy
   - Terms of Service: https://{self.domain}/terms
3. Add scopes:
   - https://www.googleapis.com/auth/gmail.readonly
   - https://www.googleapis.com/auth/gmail.modify
   - https://www.googleapis.com/auth/gmail.labels
   - openid
   - email
   - profile
4. Add test users (for development)
        """)
        
        # Create OAuth client
        oauth_config = {
            "web": {
                "authorized_redirect_uris": [
                    f"{self.backend_url}/api/v1/auth/gmail/callback"
                ],
                "authorized_javascript_origins": [
                    self.frontend_url
                ]
            }
        }
        
        # Use gcloud to create OAuth client
        with open("/tmp/oauth_config.json", "w") as f:
            json.dump(oauth_config, f)
        
        result = self.run_gcloud_command([
            "gcloud", "alpha", "iap", "oauth-brands", "create",
            "--application_title=PhishNet Email Security",
            "--support_email=support@" + self.domain,
            "--project", self.project_id,
            "--format=json"
        ])
        
        print("✅ OAuth brand created")
        
        # Create OAuth client credentials
        client_result = self.run_gcloud_command([
            "gcloud", "alpha", "iap", "oauth-clients", "create",
            f"projects/{self.project_id}/brands/{result.get('name', '').split('/')[-1]}",
            "--display_name=PhishNet Web Client",
            "--format=json"
        ])
        
        print("✅ OAuth client created")
        return client_result

    def create_pubsub_resources(self):
        """Create Pub/Sub topic and subscription for Gmail watch"""
        print("🔄 Creating Pub/Sub resources...")
        
        topic_name = "phishnet-gmail-notifications"
        subscription_name = "phishnet-gmail-sub"
        
        # Create topic
        self.run_gcloud_command([
            "gcloud", "pubsub", "topics", "create", topic_name,
            "--project", self.project_id
        ])
        
        # Create subscription
        self.run_gcloud_command([
            "gcloud", "pubsub", "subscriptions", "create", subscription_name,
            "--topic", topic_name,
            "--project", self.project_id
        ])
        
        # Create service account for Pub/Sub
        service_account_email = f"phishnet-gmail@{self.project_id}.iam.gserviceaccount.com"
        
        self.run_gcloud_command([
            "gcloud", "iam", "service-accounts", "create", "phishnet-gmail",
            "--display-name", "PhishNet Gmail Integration",
            "--project", self.project_id
        ])
        
        # Grant permissions
        permissions = [
            "roles/pubsub.subscriber",
            "roles/pubsub.viewer",
            "roles/gmail.readonly"
        ]
        
        for permission in permissions:
            subprocess.run([
                "gcloud", "projects", "add-iam-policy-binding", self.project_id,
                "--member", f"serviceAccount:{service_account_email}",
                "--role", permission
            ], check=True)
        
        print("✅ Pub/Sub resources created")
        return {
            "topic": f"projects/{self.project_id}/topics/{topic_name}",
            "subscription": f"projects/{self.project_id}/subscriptions/{subscription_name}",
            "service_account": service_account_email
        }

    def create_service_account_key(self, service_account_email: str) -> str:
        """Create and download service account key"""
        key_file = f"phishnet-gmail-{self.project_id}.json"
        
        subprocess.run([
            "gcloud", "iam", "service-accounts", "keys", "create", key_file,
            "--iam-account", service_account_email,
            "--project", self.project_id
        ], check=True)
        
        print(f"✅ Service account key created: {key_file}")
        print("⚠️  Store this key securely and add to your backend environment!")
        
        return key_file

    def generate_environment_config(self, oauth_client: Dict, pubsub_config: Dict, key_file: str):
        """Generate environment configuration"""
        config = f"""# PhishNet Gmail OAuth Configuration
# Generated on {import_datetime.datetime.now().isoformat()}

# Google Cloud Project
GOOGLE_CLOUD_PROJECT={self.project_id}

# OAuth 2.0 Credentials (from Google Cloud Console)
GMAIL_CLIENT_ID={oauth_client.get('clientId', 'REPLACE_WITH_CLIENT_ID')}
GMAIL_CLIENT_SECRET={oauth_client.get('clientSecret', 'REPLACE_WITH_CLIENT_SECRET')}

# OAuth Redirect URIs
GMAIL_REDIRECT_URI={self.backend_url}/api/v1/auth/gmail/callback
FRONTEND_URL={self.frontend_url}

# Pub/Sub Configuration
PUBSUB_TOPIC={pubsub_config['topic']}
PUBSUB_SUBSCRIPTION={pubsub_config['subscription']}
GOOGLE_APPLICATION_CREDENTIALS=./{key_file}

# Security Settings
ENCRYPTION_KEY=GENERATE_32_BYTE_KEY_HERE
SECRET_KEY=GENERATE_JWT_SECRET_HERE

# Additional URLs for OAuth consent
PRIVACY_POLICY_URL=https://{self.domain}/privacy
TERMS_OF_SERVICE_URL=https://{self.domain}/terms
SUPPORT_EMAIL=support@{self.domain}

# Environment
ENVIRONMENT=production
DEBUG=false
"""
        
        with open(".env.production", "w") as f:
            f.write(config)
        
        print("✅ Environment configuration saved to .env.production")

    def setup_complete_instructions(self):
        """Print final setup instructions"""
        print(f"""
🎉 Google Cloud Setup Complete!

Next Steps:
1. Complete OAuth Consent Screen setup (see URL above)
2. Update .env.production with actual client ID and secret
3. Generate encryption key: python -c "import secrets; print(secrets.token_urlsafe(32))"
4. Generate JWT secret: python -c "import secrets; print(secrets.token_urlsafe(32))"
5. Deploy service account key to your backend securely
6. Create privacy policy and terms of service pages
7. Test OAuth flow in development environment

🔗 Useful Links:
- Project Console: https://console.cloud.google.com/home/dashboard?project={self.project_id}
- OAuth Setup: https://console.cloud.google.com/apis/credentials/consent?project={self.project_id}
- API Credentials: https://console.cloud.google.com/apis/credentials?project={self.project_id}
- Pub/Sub: https://console.cloud.google.com/cloudpubsub?project={self.project_id}

⚠️  Security Reminders:
- Store client secret and service account key securely
- Use environment variables, not committed files
- Regularly rotate keys and monitor usage
- Set up proper IAM permissions for production
        """)

def main():
    parser = argparse.ArgumentParser(description="Setup Google Cloud Console for PhishNet Gmail OAuth")
    parser.add_argument("--project-id", required=True, help="Google Cloud Project ID")
    parser.add_argument("--domain", required=True, help="Your domain (e.g., phishnet.app)")
    parser.add_argument("--backend-url", required=True, help="Backend URL (e.g., https://api.phishnet.app)")
    
    args = parser.parse_args()
    
    print("🚀 PhishNet Google Cloud Setup")
    print("=" * 50)
    
    setup = GoogleCloudSetup(args.project_id, args.domain, args.backend_url)
    
    # Run setup steps
    setup.check_gcloud_auth()
    setup.create_project()
    setup.enable_apis()
    
    # Create OAuth credentials
    oauth_client = setup.create_oauth_credentials()
    
    # Create Pub/Sub resources
    pubsub_config = setup.create_pubsub_resources()
    
    # Create service account key
    key_file = setup.create_service_account_key(pubsub_config['service_account'])
    
    # Generate environment config
    setup.generate_environment_config(oauth_client, pubsub_config, key_file)
    
    # Final instructions
    setup.setup_complete_instructions()

if __name__ == "__main__":
    import datetime
    main()
