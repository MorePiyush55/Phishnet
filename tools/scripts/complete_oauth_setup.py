#!/usr/bin/env python3
"""
Complete PhishNet Gmail OAuth Setup
Comprehensive setup script for Google Cloud Console, OAuth, and Pub/Sub
"""

import argparse
import os
import sys
import json
import subprocess
import secrets
import base64
from typing import Dict, List

def generate_keys() -> Dict[str, str]:
    """Generate required encryption and JWT keys."""
    encryption_key = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode()
    jwt_secret = secrets.token_urlsafe(32)
    
    return {
        "ENCRYPTION_KEY": encryption_key,
        "SECRET_KEY": jwt_secret
    }

def create_environment_file(
    project_id: str,
    domain: str, 
    backend_url: str,
    client_id: str = "REPLACE_WITH_CLIENT_ID",
    client_secret: str = "REPLACE_WITH_CLIENT_SECRET"
):
    """Create production environment file."""
    
    keys = generate_keys()
    
    env_content = f"""# PhishNet Gmail OAuth Production Configuration
# Generated: {import_datetime.datetime.now().isoformat()}

# Google Cloud Project
GOOGLE_CLOUD_PROJECT={project_id}

# OAuth 2.0 Credentials
GMAIL_CLIENT_ID={client_id}
GMAIL_CLIENT_SECRET={client_secret}

# OAuth Configuration
GMAIL_REDIRECT_URI={backend_url}/api/v1/auth/gmail/callback
FRONTEND_URL=https://{domain}

# Pub/Sub Configuration  
PUBSUB_TOPIC=projects/{project_id}/topics/phishnet-gmail-notifications
PUBSUB_SUBSCRIPTION=projects/{project_id}/subscriptions/phishnet-gmail-sub
GOOGLE_APPLICATION_CREDENTIALS=./phishnet-gmail-{project_id}.json

# Security Settings
ENCRYPTION_KEY={keys['ENCRYPTION_KEY']}
SECRET_KEY={keys['SECRET_KEY']}

# OAuth Consent Configuration
PRIVACY_POLICY_URL=https://{domain}/privacy
TERMS_OF_SERVICE_URL=https://{domain}/terms
SUPPORT_EMAIL=support@{domain}

# Rate Limiting
OAUTH_RATE_LIMIT_PER_MINUTE=10
OAUTH_RATE_LIMIT_PER_HOUR=100

# Environment
ENVIRONMENT=production
DEBUG=false
LOG_LEVEL=INFO

# Database
DATABASE_URL=postgresql://user:password@localhost/phishnet

# Redis
REDIS_URL=redis://localhost:6379/0

# JWT Configuration
JWT_ALGORITHM=HS256
JWT_EXPIRE_MINUTES=30
REFRESH_TOKEN_EXPIRE_DAYS=7

# PhishNet API
API_V1_PREFIX=/api/v1
CORS_ORIGINS=https://{domain}

# Gmail API Configuration
GMAIL_SCOPES=https://www.googleapis.com/auth/gmail.readonly,https://www.googleapis.com/auth/gmail.modify,https://www.googleapis.com/auth/gmail.labels,openid,email,profile

# Monitoring
HEALTH_CHECK_INTERVAL=300
OAUTH_TOKEN_CHECK_INTERVAL=3600

# Pub/Sub Configuration
PUBSUB_MAX_MESSAGES=100
PUBSUB_ACK_DEADLINE=600
"""
    
    with open(".env.production", "w") as f:
        f.write(env_content)
    
    print("✅ Created .env.production")

def create_oauth_client_template():
    """Create OAuth client configuration template."""
    
    config = {
        "web": {
            "client_id": "REPLACE_WITH_ACTUAL_CLIENT_ID",
            "client_secret": "REPLACE_WITH_ACTUAL_CLIENT_SECRET",
            "auth_uri": "https://accounts.google.com/o/oauth2/auth",
            "token_uri": "https://oauth2.googleapis.com/token",
            "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
            "redirect_uris": [],
            "javascript_origins": []
        }
    }
    
    with open("oauth_client_template.json", "w") as f:
        json.dump(config, f, indent=2)
    
    print("✅ Created oauth_client_template.json")

def create_setup_documentation(project_id: str, domain: str, backend_url: str):
    """Create comprehensive setup documentation."""
    
    doc_content = f"""# PhishNet Gmail OAuth Setup Guide

## Overview
Complete setup guide for PhishNet's Gmail OAuth integration with Google Cloud Console.

## Prerequisites
- Google Cloud Account with billing enabled
- gcloud CLI installed and authenticated
- Domain ownership verified: {domain}
- Backend deployed at: {backend_url}

## Quick Setup

### 1. Run Google Cloud Setup Script
```bash
# Make script executable (Linux/Mac)
chmod +x scripts/Setup-GoogleCloud.ps1

# Run setup (PowerShell)
./scripts/Setup-GoogleCloud.ps1 -ProjectId "{project_id}" -Domain "{domain}" -BackendUrl "{backend_url}"
```

### 2. Manual Google Cloud Console Steps

#### OAuth Consent Screen
1. Go to: https://console.cloud.google.com/apis/credentials/consent?project={project_id}
2. Configure:
   - Application name: PhishNet Email Security
   - User support email: support@{domain}
   - Authorized domains: {domain}
   - Privacy Policy: https://{domain}/privacy
   - Terms of Service: https://{domain}/terms

#### Required Scopes
Add these scopes in the OAuth consent screen:
- `https://www.googleapis.com/auth/gmail.readonly`
- `https://www.googleapis.com/auth/gmail.modify`
- `https://www.googleapis.com/auth/gmail.labels`
- `openid`
- `email`
- `profile`

#### Create OAuth Credentials
1. Go to: https://console.cloud.google.com/apis/credentials?project={project_id}
2. Click "Create Credentials" > "OAuth client ID"
3. Select "Web application"
4. Name: "PhishNet Web Client"
5. Authorized JavaScript origins: `https://{domain}`
6. Authorized redirect URIs: `{backend_url}/api/v1/auth/gmail/callback`
7. Save client ID and secret

### 3. Environment Configuration
1. Update `.env.production` with OAuth credentials:
   ```bash
   GMAIL_CLIENT_ID=your_actual_client_id
   GMAIL_CLIENT_SECRET=your_actual_client_secret
   ```

2. Deploy service account key securely to your backend

### 4. Database Migration
```bash
# Run migration to add Gmail watch fields
alembic upgrade gmail_watch_fields
```

### 5. Privacy Policy & Terms Pages
Create these pages on your domain:
- https://{domain}/privacy
- https://{domain}/terms

## Testing

### Test OAuth Flow
1. Visit your frontend application
2. Click "Connect Gmail" 
3. Complete OAuth flow
4. Verify connection status

### Test Pub/Sub Notifications
```bash
# Send test notification
python scripts/test_pubsub.py --project-id {project_id}
```

### Test API Endpoints
```bash
# Test OAuth status
curl -H "Authorization: Bearer YOUR_JWT" {backend_url}/api/v1/auth/gmail/status

# Test Gmail watch setup
curl -X POST -H "Authorization: Bearer YOUR_JWT" {backend_url}/api/v1/auth/gmail/watch/setup

# Test message retrieval
curl -H "Authorization: Bearer YOUR_JWT" {backend_url}/api/v1/auth/gmail/messages
```

## Production Deployment

### Security Checklist
- [ ] Client secret stored in secure environment variables
- [ ] Service account key deployed securely
- [ ] Rate limiting configured
- [ ] Audit logging enabled
- [ ] Privacy policy and terms pages live
- [ ] SSL/TLS configured for all endpoints
- [ ] CORS properly configured
- [ ] Database migrations applied

### Monitoring Setup
- Monitor OAuth token refresh rates
- Watch Pub/Sub message processing
- Track API rate limits
- Monitor Gmail watch expirations

### Scaling Considerations
- Pub/Sub subscription scaling
- Database connection pooling
- Redis session management
- OAuth token storage optimization

## Troubleshooting

### Common Issues

#### OAuth Consent Screen Verification
If publishing to production (beyond test users):
1. Submit app for verification
2. Provide privacy policy and terms
3. Answer Google's verification questionnaire
4. Wait for approval (can take weeks)

#### Pub/Sub Permission Issues
Ensure service account has:
- `roles/pubsub.subscriber`
- `roles/pubsub.viewer`
- Gmail API access

#### Token Refresh Failures
Check:
- Service account key validity
- Network connectivity to Google APIs
- Database token storage
- Encryption key consistency

## Support
- Documentation: docs/
- Issues: GitHub repository
- Email: support@{domain}

## Security Notes
- Regularly rotate service account keys
- Monitor OAuth token usage patterns
- Implement proper logging and alerting
- Keep dependencies updated
- Follow Google's security best practices
"""
    
    with open("GMAIL_OAUTH_SETUP.md", "w") as f:
        f.write(doc_content)
    
    print("✅ Created GMAIL_OAUTH_SETUP.md")

def create_test_script():
    """Create Pub/Sub test script."""
    
    test_script = '''#!/usr/bin/env python3
"""Test Pub/Sub notifications for PhishNet Gmail integration."""

import json
import base64
import argparse
from google.cloud import pubsub_v1

def send_test_notification(project_id: str, topic_name: str = "phishnet-gmail-notifications"):
    """Send a test Pub/Sub notification."""
    
    publisher = pubsub_v1.PublisherClient()
    topic_path = publisher.topic_path(project_id, topic_name)
    
    # Create test Gmail notification
    test_data = {
        "emailAddress": "test@example.com",
        "historyId": "12345"
    }
    
    # Encode as Pub/Sub expects
    message_data = json.dumps(test_data).encode()
    encoded_data = base64.b64encode(message_data).decode()
    
    notification = {
        "message": {
            "data": encoded_data,
            "messageId": "test-message-123",
            "publishTime": "2025-01-13T10:00:00.000Z"
        }
    }
    
    # Publish test message
    future = publisher.publish(topic_path, json.dumps(notification).encode())
    message_id = future.result()
    
    print(f"✅ Published test notification: {message_id}")
    print(f"Topic: {topic_path}")
    print(f"Data: {test_data}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--project-id", required=True)
    parser.add_argument("--topic", default="phishnet-gmail-notifications")
    
    args = parser.parse_args()
    send_test_notification(args.project_id, args.topic)
'''
    
    with open("scripts/test_pubsub.py", "w") as f:
        f.write(test_script)
    
    print("✅ Created scripts/test_pubsub.py")

def main():
    parser = argparse.ArgumentParser(description="Complete PhishNet Gmail OAuth Setup")
    parser.add_argument("--project-id", required=True, help="Google Cloud Project ID")
    parser.add_argument("--domain", required=True, help="Your domain (e.g., phishnet.app)")
    parser.add_argument("--backend-url", required=True, help="Backend URL (e.g., https://api.phishnet.app)")
    parser.add_argument("--client-id", help="OAuth Client ID (if already created)")
    parser.add_argument("--client-secret", help="OAuth Client Secret (if already created)")
    
    args = parser.parse_args()
    
    print("🚀 PhishNet Gmail OAuth Complete Setup")
    print("=" * 50)
    print(f"Project ID: {args.project_id}")
    print(f"Domain: {args.domain}")
    print(f"Backend: {args.backend_url}")
    print()
    
    # Create all configuration files
    create_environment_file(
        args.project_id,
        args.domain,
        args.backend_url,
        args.client_id or "REPLACE_WITH_CLIENT_ID",
        args.client_secret or "REPLACE_WITH_CLIENT_SECRET"
    )
    
    create_oauth_client_template()
    create_setup_documentation(args.project_id, args.domain, args.backend_url)
    create_test_script()
    
    print()
    print("🎉 Setup files created successfully!")
    print()
    print("Next steps:")
    print("1. Run: ./scripts/Setup-GoogleCloud.ps1 (for Google Cloud resources)")
    print("2. Complete OAuth consent screen setup (see GMAIL_OAUTH_SETUP.md)")
    print("3. Create OAuth credentials and update .env.production")
    print("4. Deploy service account key securely")
    print("5. Run database migration: alembic upgrade gmail_watch_fields")
    print("6. Test OAuth flow with your application")
    print()
    print("📚 See GMAIL_OAUTH_SETUP.md for detailed instructions")

if __name__ == "__main__":
    import datetime
    main()
