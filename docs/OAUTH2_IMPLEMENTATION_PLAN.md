# Google OAuth2 Gmail Integration Implementation Plan

## Executive Summary

This document provides a production-grade, step-by-step implementation plan for integrating Google OAuth2 authentication with PhishNet to enable secure, auditable access to users' Gmail accounts for real-time phishing analysis.

## Architecture Overview

**High-Level Flow**: Authorization Code Flow (server-side)
- Frontend triggers backend OAuth initiation endpoint
- Backend builds Google auth URL with state/PKCE parameters  
- User completes consent at Google OAuth server
- Google redirects to backend callback endpoint
- Backend exchanges authorization code for access/refresh tokens
- Backend stores encrypted refresh token tied to user account
- Backend performs Gmail API operations and communicates status to frontend

## Phase 1: Database Schema Design

### 1.1 OAuth Token Storage Model Enhancement

**File**: `app/models/oauth.py` (new file)

**Requirements**:
- Extend existing `OAuthToken` model in `user.py`
- Add encrypted storage for refresh tokens
- Include audit trail fields
- Support token rotation and revocation
- Store OAuth2 state and PKCE verifiers

**Fields to Add**:
```
- encrypted_access_token: TEXT (AES-256 encrypted)
- encrypted_refresh_token: TEXT (AES-256 encrypted) 
- access_token_expires_at: DATETIME
- refresh_token_expires_at: DATETIME
- oauth_state: VARCHAR(255) (for CSRF protection)
- pkce_code_verifier: VARCHAR(128) (for PKCE flow)
- granted_scopes: TEXT (JSON array of actual granted scopes)
- revoked_at: DATETIME
- revocation_reason: VARCHAR(255)
- last_used_at: DATETIME
- token_version: INTEGER (for token rotation)
```

### 1.2 Gmail Permission Audit Model

**File**: `app/models/gmail_audit.py` (new file)

**Purpose**: Track all Gmail API operations for compliance and security

**Fields**:
```
- user_id: INTEGER (foreign key)
- operation_type: ENUM (read_email, modify_email, list_messages, etc.)
- gmail_message_id: VARCHAR(255)
- operation_timestamp: DATETIME
- ip_address: VARCHAR(45)
- user_agent: TEXT
- operation_result: ENUM (success, failure, rate_limited)
- error_details: TEXT
- data_accessed: TEXT (summary of data accessed)
```

### 1.3 User Consent Tracking Model

**File**: `app/models/consent.py` (new file)

**Purpose**: Track user consent for GDPR/privacy compliance

**Fields**:
```
- user_id: INTEGER (foreign key)
- consent_type: ENUM (gmail_access, data_processing, email_modification)
- consent_granted: BOOLEAN
- consent_timestamp: DATETIME
- consent_withdrawn_at: DATETIME
- privacy_policy_version: VARCHAR(50)
- ip_address: VARCHAR(45)
- user_agent: TEXT
```

## Phase 2: Backend OAuth2 Endpoints

### 2.1 OAuth Initiation Endpoint

**File**: `app/api/v1/oauth.py` (new file)

**Endpoint**: `POST /api/v1/oauth/gmail/initiate`

**Purpose**: Start OAuth2 flow with security measures

**Implementation Requirements**:
- Generate cryptographically secure state parameter
- Generate PKCE code verifier and challenge
- Store state and PKCE verifier in Redis with TTL
- Build Google OAuth URL with proper scopes
- Return authorization URL to frontend

**Security Features**:
- Rate limiting (5 requests per minute per user)
- CSRF state validation
- PKCE for public clients
- Scope validation
- User authentication required

**Response**:
```json
{
  "authorization_url": "https://accounts.google.com/oauth/v2/auth?...",
  "state": "cryptographically_secure_state_value"
}
```

### 2.2 OAuth Callback Endpoint

**File**: `app/api/v1/oauth.py`

**Endpoint**: `GET /api/v1/oauth/gmail/callback`

**Purpose**: Handle Google OAuth callback and token exchange

**Implementation Requirements**:
- Validate state parameter against stored value
- Validate PKCE code verifier
- Exchange authorization code for tokens
- Encrypt and store refresh token
- Create audit log entry
- Redirect user to frontend success page

**Security Features**:
- State validation (CSRF protection)
- PKCE validation
- Token encryption before storage
- Immediate code exchange (prevents replay attacks)
- Comprehensive audit logging

### 2.3 Token Management Endpoints

**File**: `app/api/v1/oauth.py`

**Endpoints**:
- `GET /api/v1/oauth/gmail/status` - Check connection status
- `POST /api/v1/oauth/gmail/refresh` - Manually refresh tokens  
- `DELETE /api/v1/oauth/gmail/revoke` - Revoke access and delete tokens

**Implementation Requirements**:
- Token rotation on refresh
- Secure token validation
- Graceful error handling for expired/invalid tokens
- Audit logging for all operations

### 2.4 Gmail Operations Endpoints

**File**: `app/api/v1/gmail.py` (enhance existing)

**Endpoints**:
- `POST /api/v1/gmail/scan/trigger` - Trigger manual scan
- `GET /api/v1/gmail/scan/status/{scan_id}` - Get scan status
- `GET /api/v1/gmail/permissions` - Get current permissions
- `POST /api/v1/gmail/permissions/verify` - Verify token validity

## Phase 3: Frontend OAuth2 Integration

### 3.1 Gmail Connection Component

**File**: `frontend/src/components/GmailConnect.tsx` (new file)

**Purpose**: Main Gmail connection interface

**Features**:
- Clear explanation of permissions and usage
- Connect/disconnect buttons
- Connection status display
- Permission verification
- Error handling and user feedback

**User Experience Flow**:
1. Display connection status (connected/disconnected)
2. Show "Connect Gmail" button with permission explanation
3. Open consent modal on button click
4. Handle OAuth flow completion
5. Display success/error messages
6. Show connected account information

### 3.2 Consent Modal Component

**File**: `frontend/src/components/GmailConsentModal.tsx` (new file)

**Purpose**: Detailed consent and permission disclosure

**Content Requirements**:
- Clear scope explanations in plain language
- Data usage and retention policies
- Links to privacy policy and data deletion
- Explicit consent checkboxes
- Cancel and proceed buttons

**Information to Display**:
- "Read and analyze email content for phishing detection"
- "Apply labels or move emails to quarantine when malicious content is detected"
- "We will never send your emails to third-party services with your personal information"
- "You can revoke access at any time"

### 3.3 Gmail Status Dashboard

**File**: `frontend/src/components/GmailStatus.tsx` (new file)

**Purpose**: Show Gmail integration status and controls

**Features**:
- Connected account email display
- Last scan timestamp
- Manual "Scan Now" button
- "Disconnect" button
- Permission audit log (basic view)
- Connection health status

### 3.4 OAuth Service Integration

**File**: `frontend/src/services/oauthService.ts` (new file)

**Purpose**: Handle OAuth API communications

**Functions**:
- `initiateGmailOAuth()` - Start OAuth flow
- `checkGmailStatus()` - Get connection status
- `revokeGmailAccess()` - Disconnect Gmail
- `triggerManualScan()` - Start manual scan
- `getPermissionAudit()` - Get audit log

## Phase 4: Google Cloud Console Setup

### 4.1 OAuth2 Credentials Configuration

**Steps**:
1. Create new project or use existing in Google Cloud Console
2. Enable Gmail API
3. Configure OAuth consent screen:
   - App name: "PhishNet Email Security"
   - Authorized domains: yourdomain.com, vercel.app
   - Privacy policy URL: https://yourdomain.com/privacy
   - Terms of service URL: https://yourdomain.com/terms
4. Create OAuth 2.0 client credentials:
   - Application type: Web application
   - Authorized redirect URIs: 
     - https://your-backend.render.com/api/v1/oauth/gmail/callback
     - https://localhost:8000/api/v1/oauth/gmail/callback (for development)

### 4.2 Scope Configuration

**Required Scopes**:
- `https://www.googleapis.com/auth/gmail.readonly` - Read email content
- `https://www.googleapis.com/auth/gmail.modify` - Label and quarantine emails

**Scope Justification Documentation**:
- Document why each scope is needed
- Prepare for Google OAuth verification process
- Create scope usage audit trail

### 4.3 Domain Verification

**Requirements**:
- Verify ownership of production domain
- Configure proper DNS records
- Set up domain-wide delegation if needed for enterprise

## Phase 5: Security & Privacy Implementation

### 5.1 Token Encryption Strategy

**Implementation**:
- Use AES-256-GCM for token encryption
- Derive encryption keys from master key + user salt
- Store encryption keys in environment variables or key management service
- Implement key rotation strategy

**File**: `app/core/encryption.py` (enhance existing)

### 5.2 Audit Logging System

**Requirements**:
- Log all OAuth operations (grant, refresh, revoke)
- Log all Gmail API calls with metadata
- Include IP address, user agent, timestamp
- Store audit logs in separate table with retention policy
- Implement log rotation and archival

**File**: `app/services/audit_service.py` (new file)

### 5.3 Privacy Compliance Features

**GDPR Compliance**:
- Data deletion endpoint for user requests
- Consent tracking and management
- Data export functionality
- Clear retention policies

**File**: `app/api/v1/privacy.py` (new file)

**Endpoints**:
- `POST /api/v1/privacy/delete-data` - Delete all user data
- `GET /api/v1/privacy/export-data` - Export user data
- `GET /api/v1/privacy/consent-history` - View consent history

### 5.4 Rate Limiting and Abuse Prevention

**Implementation**:
- Implement strict rate limiting on OAuth endpoints
- Monitor for suspicious authorization patterns
- Implement token usage monitoring
- Set up alerts for unusual access patterns

## Phase 6: Testing Strategy

### 6.1 Unit Tests

**Files to Create**:
- `tests/test_oauth_endpoints.py`
- `tests/test_gmail_service.py`
- `tests/test_token_encryption.py`
- `tests/test_audit_logging.py`

**Test Coverage**:
- OAuth flow initiation and callback handling
- Token encryption/decryption
- PKCE validation
- State parameter validation
- Error handling scenarios

### 6.2 Integration Tests

**Files to Create**:
- `tests/integration/test_oauth_flow.py`
- `tests/integration/test_gmail_operations.py`

**Test Scenarios**:
- Complete OAuth flow end-to-end
- Token refresh scenarios
- Error handling and recovery
- Rate limiting behavior

### 6.3 Security Tests

**Files to Create**:
- `tests/security/test_oauth_security.py`
- `tests/security/test_token_security.py`

**Security Test Cases**:
- CSRF protection validation
- Token replay attack prevention
- Encryption key security
- SQL injection prevention

### 6.4 Frontend Tests

**Files to Create**:
- `frontend/src/components/__tests__/GmailConnect.test.tsx`
- `frontend/src/services/__tests__/oauthService.test.ts`

## Phase 7: Deployment Checklist

### 7.1 Environment Variables

**Backend (Render)**:
```
GOOGLE_OAUTH_CLIENT_ID=your_client_id
GOOGLE_OAUTH_CLIENT_SECRET=your_client_secret
OAUTH_ENCRYPTION_KEY=base64_encoded_key
OAUTH_REDIRECT_URI=https://your-backend.render.com/api/v1/oauth/gmail/callback
FRONTEND_URL=https://your-frontend.vercel.app
```

**Frontend (Vercel)**:
```
REACT_APP_API_BASE_URL=https://your-backend.render.com
REACT_APP_OAUTH_ENABLED=true
```

### 7.2 Database Migration

**Files**:
- Create Alembic migration for new OAuth tables
- Test migration on staging environment
- Plan rollback strategy

### 7.3 Security Checklist

**Production Deployment**:
- [ ] SSL/TLS certificates configured
- [ ] Environment variables properly secured
- [ ] Rate limiting configured
- [ ] Audit logging enabled
- [ ] Error monitoring set up
- [ ] Token encryption tested
- [ ] Backup and recovery tested

### 7.4 Monitoring and Alerting

**Metrics to Monitor**:
- OAuth flow completion rates
- Token refresh success rates
- Gmail API error rates
- Security event alerts
- Performance metrics

**Alert Conditions**:
- High OAuth failure rates
- Unusual token access patterns
- Gmail API rate limit hits
- Security violations

## Implementation Timeline

**Week 1-2**: Database schema and backend OAuth endpoints
**Week 3**: Frontend components and OAuth integration  
**Week 4**: Security features and audit logging
**Week 5**: Testing and security validation
**Week 6**: Deployment and monitoring setup

## Risk Mitigation

**Security Risks**:
- Token theft: Implement encryption and rotation
- CSRF attacks: Use state parameters and PKCE
- Replay attacks: Implement nonce validation

**Operational Risks**:
- Google API quota limits: Implement rate limiting and caching
- Token expiration: Implement automatic refresh
- Service downtime: Implement circuit breakers and fallbacks

**Privacy Risks**:
- Data retention: Implement clear retention policies
- User consent: Implement explicit consent tracking
- Data breaches: Implement encryption and access controls
