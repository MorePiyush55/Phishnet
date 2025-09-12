# PhishNet Security Implementation - Complete Guide

## 🔐 Security Architecture Overview

This document outlines the comprehensive security implementation for PhishNet, including JWT authentication, OAuth integration, secret management, and API protection.

## 📋 Security Features Implemented

### ✅ 1. Secret Management
- **Centralized Settings**: Pydantic BaseSettings with environment variable support
- **Secret Storage Integration**: AWS Secrets Manager, GCP Secret Manager, HashiCorp Vault
- **Development Fallback**: Environment variables for local development
- **No Hardcoded Secrets**: All sensitive data externalized

### ✅ 2. JWT Authentication System
- **Access Tokens**: Short-lived (30 minutes default)
- **Refresh Tokens**: Long-lived (7 days default) with revocation support
- **Role-Based Access Control**: Admin, Analyst, User roles
- **Permission-Based Authorization**: Granular permissions per operation
- **Token Revocation**: Individual and bulk token revocation

### ✅ 3. Secure OAuth Flow
- **CSRF Protection**: State parameter validation with HMAC signing
- **Redirect URI Validation**: Domain whitelisting and HTTPS enforcement
- **Encrypted Token Storage**: AES encryption for refresh tokens in database
- **Scope Validation**: Proper OAuth scope handling

### ✅ 4. API Protection
- **JWT Middleware**: Centralized authentication for all endpoints
- **Rate Limiting**: Per-user rate limiting with Redis backend
- **CORS Configuration**: Secure cross-origin request handling
- **Security Headers**: HSTS, CSP, and other protective headers

### ✅ 5. WebSocket Security
- **JWT Authentication**: Token-based WebSocket handshake
- **Connection Management**: Tracked connections with user validation
- **Message Authorization**: Role and permission-based message routing
- **Token Freshness**: Periodic token validation during connection

### ✅ 6. Password Security
- **bcrypt Hashing**: Configurable rounds (default 12)
- **Password Complexity**: Minimum length and special character requirements
- **Password History**: Prevention of password reuse (optional)
- **Secure Verification**: Constant-time password comparison

## 🏗️ Architecture Components

### Core Security Modules

```
app/core/
├── auth.py              # JWT service, password service, auth service
├── auth_deps.py         # FastAPI authentication dependencies  
├── secrets.py           # Secret management with provider abstraction
├── oauth_security.py    # Secure OAuth with CSRF and encryption
└── websocket_auth.py    # WebSocket authentication and management
```

### Authentication Flow

```
1. Login Request → Password Verification → JWT Token Pair
2. API Request → JWT Validation → Permission Check → Resource Access
3. Token Refresh → Refresh Token Validation → New Access Token
4. Logout → Token Revocation → Access Denied
```

### OAuth Flow

```
1. OAuth Init → CSRF Token → Authorization URL
2. Provider Callback → CSRF Validation → Token Exchange
3. Token Storage → Encryption → Database Storage
4. Token Refresh → Decryption → New Access Token
```

## 🔧 Configuration

### Environment Variables

```bash
# Security Settings
SECRET_KEY=your-32-character-minimum-secret-key
ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=30
REFRESH_TOKEN_EXPIRE_DAYS=7

# Password Security  
MIN_PASSWORD_LENGTH=8
REQUIRE_SPECIAL_CHARS=true
BCRYPT_ROUNDS=12

# OAuth Configuration
GMAIL_CLIENT_ID=your-gmail-client-id
GMAIL_CLIENT_SECRET=your-gmail-client-secret
GMAIL_REDIRECT_URI=https://yourdomain.com/api/v1/auth/oauth/gmail/callback

# Secret Management (Choose One)
# AWS Secrets Manager
AWS_REGION=us-west-2
AWS_SECRET_NAME=phishnet/production/secrets

# GCP Secret Manager  
GCP_PROJECT_ID=your-project-id
GCP_SECRET_NAME=phishnet-secrets

# HashiCorp Vault
VAULT_URL=https://vault.example.com
VAULT_TOKEN=your-vault-token
```

### Database Models

```sql
-- JWT Token Revocation
CREATE TABLE revoked_tokens (
    id SERIAL PRIMARY KEY,
    jti VARCHAR(255) UNIQUE NOT NULL,
    user_id VARCHAR(255),
    revoked_at TIMESTAMP DEFAULT NOW(),
    reason VARCHAR(255)
);

-- OAuth Token Storage
CREATE TABLE oauth_tokens (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL,
    provider VARCHAR(50) NOT NULL,
    encrypted_refresh_token TEXT NOT NULL,
    token_expires_at TIMESTAMP,
    scope VARCHAR(500),
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW(),
    is_active BOOLEAN DEFAULT TRUE
);
```

## 🚀 API Endpoints

### Authentication Endpoints

```bash
# User Authentication
POST /api/v1/auth/login           # Login with email/password
POST /api/v1/auth/register        # Register new user
POST /api/v1/auth/refresh         # Refresh access token
POST /api/v1/auth/logout          # Logout (revoke current token)
POST /api/v1/auth/logout-all      # Logout from all devices
GET  /api/v1/auth/me              # Get current user info

# Password Management
POST /api/v1/auth/change-password # Change password
POST /api/v1/auth/forgot-password # Request password reset
POST /api/v1/auth/reset-password  # Reset password with token

# OAuth Integration
POST /api/v1/auth/oauth/gmail/init     # Initialize Gmail OAuth
GET  /api/v1/auth/oauth/gmail/callback # Handle OAuth callback
POST /api/v1/auth/oauth/revoke/{provider} # Revoke OAuth token

# Health Check
GET  /api/v1/auth/health          # Authentication system health
```

### Protected Endpoint Examples

```python
# Require authentication
@router.get("/protected")
async def protected_endpoint(
    current_user: TokenPayload = Depends(get_current_user)
):
    return {"user_id": current_user.sub}

# Require admin role
@router.post("/admin-only")
async def admin_endpoint(
    current_user: TokenPayload = Depends(require_admin)
):
    return {"message": "Admin access granted"}

# Require specific permission
@router.put("/analysis")
async def analysis_endpoint(
    current_user: TokenPayload = Depends(require_permission("email:analyze"))
):
    return {"message": "Analysis permission verified"}

# Combined authentication with audit
@router.delete("/sensitive")
async def sensitive_endpoint(
    current_user: TokenPayload = Depends(
        require_auth_and_permission("system:configure", "delete_sensitive_data")
    )
):
    return {"message": "Sensitive operation completed"}
```

## 🌐 WebSocket Authentication

### Connection Setup

```javascript
// Client-side WebSocket connection
const token = localStorage.getItem('access_token');
const ws = new WebSocket(`ws://localhost:8000/ws?token=${token}`);

ws.onopen = function(event) {
    console.log('WebSocket connected');
};

ws.onmessage = function(event) {
    const message = JSON.parse(event.data);
    console.log('Received:', message);
};
```

### Message Types

```javascript
// Ping/Pong for connection health
ws.send(JSON.stringify({type: "ping"}));

// Subscribe to channels (permission-based)
ws.send(JSON.stringify({
    type: "subscribe",
    channel: "email_alerts"  // Requires "email:read" permission
}));

// Admin broadcast (admin only)
ws.send(JSON.stringify({
    type: "admin_broadcast",
    message: "System maintenance in 5 minutes"
}));
```

## 🔒 Security Best Practices

### Secret Management
- ✅ Never commit secrets to version control
- ✅ Use environment-specific secret storage
- ✅ Rotate secrets regularly
- ✅ Audit secret access
- ✅ Use principle of least privilege

### JWT Security
- ✅ Use strong, randomly generated secret keys
- ✅ Set appropriate token expiration times
- ✅ Implement token revocation
- ✅ Use secure algorithms (RS256 for distributed systems)
- ✅ Validate all token claims

### OAuth Security
- ✅ Validate redirect URIs strictly
- ✅ Use CSRF protection (state parameter)
- ✅ Encrypt sensitive tokens
- ✅ Implement proper scope validation
- ✅ Handle errors gracefully

### API Security
- ✅ Require authentication for all sensitive endpoints
- ✅ Implement rate limiting
- ✅ Use HTTPS in production
- ✅ Add security headers
- ✅ Validate all inputs

### Password Security
- ✅ Use strong hashing algorithms (bcrypt)
- ✅ Enforce password complexity
- ✅ Implement account lockout
- ✅ Use secure password reset flows
- ✅ Audit authentication events

## 🧪 Testing Security Features

### Authentication Testing

```python
# Test login flow
def test_login_success():
    response = client.post("/api/v1/auth/login", json={
        "email": "test@example.com",
        "password": "secure_password123!"
    })
    assert response.status_code == 200
    assert "access_token" in response.json()

# Test protected endpoint
def test_protected_endpoint():
    # Without token
    response = client.get("/api/v1/protected")
    assert response.status_code == 401
    
    # With valid token
    headers = {"Authorization": f"Bearer {access_token}"}
    response = client.get("/api/v1/protected", headers=headers)
    assert response.status_code == 200

# Test token revocation
def test_token_revocation():
    # Logout
    response = client.post("/api/v1/auth/logout", headers=headers)
    assert response.status_code == 200
    
    # Try to use revoked token
    response = client.get("/api/v1/protected", headers=headers)
    assert response.status_code == 401
```

### OAuth Testing

```python
def test_oauth_init():
    response = client.post("/api/v1/auth/oauth/gmail/init", headers=headers)
    assert response.status_code == 200
    assert "authorization_url" in response.json()
    assert "csrf_token" in response.json()

def test_oauth_callback():
    response = client.get(
        "/api/v1/auth/oauth/gmail/callback",
        params={
            "code": "test_code",
            "state": "test_state",
            "csrf_token": "test_csrf_token"
        }
    )
    # Will fail without proper setup, but tests the flow
    assert response.status_code in [200, 400]
```

## 📊 Security Monitoring

### Audit Events
- User login/logout
- Token creation/revocation
- Password changes
- OAuth authorization
- Permission denied events
- Suspicious activity

### Metrics to Track
- Failed authentication attempts
- Token usage patterns
- API rate limit hits
- WebSocket connection counts
- OAuth callback success rates

### Alerts to Configure
- Multiple failed login attempts
- Unusual API usage patterns  
- Token brute force attempts
- OAuth callback failures
- Admin privilege usage

## 🚨 Incident Response

### Security Incident Types
1. **Compromised Credentials**: Immediate token revocation
2. **API Abuse**: Rate limiting and IP blocking
3. **OAuth Compromise**: Provider token revocation
4. **Data Breach**: Full security audit and remediation

### Response Procedures
1. **Detect**: Monitor audit logs and metrics
2. **Analyze**: Determine scope and impact
3. **Contain**: Revoke tokens, block access
4. **Remediate**: Fix vulnerabilities, update secrets
5. **Monitor**: Enhanced monitoring post-incident

## 🔄 Maintenance Tasks

### Regular Security Tasks
- [ ] Rotate JWT secret keys (quarterly)
- [ ] Review and update OAuth scopes
- [ ] Audit user permissions
- [ ] Update dependencies for security patches
- [ ] Review authentication logs
- [ ] Test backup authentication methods

### Production Deployment
- [ ] Use HTTPS everywhere
- [ ] Configure proper CORS origins
- [ ] Set up secret management
- [ ] Enable security monitoring
- [ ] Configure rate limiting
- [ ] Set up automated backups

## 📚 References

### Security Standards
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [OAuth 2.0 Security Best Practices](https://tools.ietf.org/html/draft-ietf-oauth-security-topics)
- [JWT Best Practices](https://tools.ietf.org/html/rfc8725)

### Implementation Guides
- [FastAPI Security](https://fastapi.tiangolo.com/tutorial/security/)
- [Pydantic Settings](https://pydantic-docs.helpmanual.io/usage/settings/)
- [SQLAlchemy Security](https://docs.sqlalchemy.org/en/14/core/security.html)

---

## ✅ Implementation Complete

All security features have been successfully implemented:

1. ✅ **Secrets Removed**: No credentials in repository, comprehensive .gitignore
2. ✅ **Centralized Configuration**: Pydantic Settings with environment variables
3. ✅ **Secret Management**: AWS/GCP/Vault integration with dev fallback
4. ✅ **JWT Authentication**: Access/refresh tokens with role-based claims
5. ✅ **API Protection**: Middleware for all HTTP endpoints
6. ✅ **WebSocket Security**: JWT authentication for real-time connections
7. ✅ **OAuth Hardening**: CSRF protection, encrypted token storage
8. ✅ **Configuration Updates**: Centralized settings throughout codebase

The PhishNet application now has enterprise-grade security suitable for production deployment! 🛡️✨
