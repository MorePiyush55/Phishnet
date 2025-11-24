# PhishNet Dual-Mode Email Verification Architecture

## 📋 Overview

PhishNet supports **two distinct modes** for email verification, each designed for different user needs and privacy preferences:

1. **Mode 1: Bulk Forward Mode** (IMAP-based) - For users who want all emails automatically scanned
2. **Mode 2: On-Demand Check Mode** (Gmail API + Message ID) - For privacy-conscious users who only share suspicious emails

---

## 🎯 Mode 1: Bulk Forward Mode (IMAP-based)

### Description
Users forward ALL their emails to a PhishNet inbox, where they are automatically scanned and scored. Results appear in the PhishNet dashboard.

### Use Case
- Users who want comprehensive, automated protection
- Organizations monitoring all incoming emails
- Users who trust PhishNet with full email access

### Architecture

```
┌─────────────┐         ┌──────────────┐         ┌──────────────┐
│   User's    │ Forward │   PhishNet   │  IMAP   │   PhishNet   │
│  Gmail/     │────────>│   Dedicated  │────────>│   Analysis   │
│  Outlook    │   All   │    Inbox     │  Poll   │   Pipeline   │
└─────────────┘  Emails └──────────────┘         └──────────────┘
                                                         │
                                                         v
                                                  ┌──────────────┐
                                                  │  Dashboard   │
                                                  │  All Scores  │
                                                  └──────────────┘
```

### Technical Implementation

#### IMAP Configuration
- **Service**: `QuickIMAPService` (`app/services/quick_imap.py`)
- **Endpoint**: `/api/v1/imap-emails/*`
- **Authentication**: IMAP credentials for PhishNet dedicated inbox
- **Polling**: Regular intervals (configurable)

#### Data Flow
1. User forwards email to `phishnet@example.com`
2. IMAP service polls inbox every X minutes
3. New emails are fetched and parsed
4. Full email content sent to analysis pipeline
5. Results stored in database with full email text
6. Dashboard displays all analyzed emails

#### Privacy Considerations
- **Data Storage**: Full email content stored indefinitely (or per retention policy)
- **Access**: PhishNet has access to all forwarded emails
- **Consent**: User explicitly forwards emails, implying consent
- **Deletion**: User can request deletion of specific emails or all data

### Configuration

```env
# IMAP Settings
IMAP_HOST=imap.gmail.com
IMAP_PORT=993
IMAP_EMAIL=phishnet@example.com
IMAP_PASSWORD=<secure-password>
IMAP_POLL_INTERVAL=300  # seconds

# Data Retention
BULK_MODE_RETENTION_DAYS=90  # Auto-delete after 90 days
```

---

## 🔒 Mode 2: On-Demand Check Mode (Gmail API + Message ID)

### Description
Users remain logged into Gmail and can click "Check with PhishNet" on specific suspicious emails. Only that single email is analyzed, with minimal scope and just-in-time permissions.

### Use Case
- Privacy-conscious users
- Users who only need occasional phishing checks
- Users who want to keep emails in their own Gmail account
- Compliance with strict data privacy requirements

### Architecture

```
┌─────────────┐                                    ┌──────────────┐
│   User's    │  Click "Check this"                │  Incremental │
│   Gmail     │  on suspicious email               │    OAuth     │
│  (Browser)  │───────────────────────────────────>│  gmail.      │
└─────────────┘                                    │  readonly    │
       │                                           └──────────────┘
       │ messageId                                        │
       v                                                  v
┌─────────────┐                                    ┌──────────────┐
│  PhishNet   │<── Send messageId ────────────────│   Backend    │
│  Frontend   │                                    │   Validates  │
└─────────────┘                                    │   Token      │
       │                                           └──────────────┘
       │ Analysis result                                  │
       v                                                  v
┌─────────────┐                                    ┌──────────────┐
│  Display    │<── Score + Reasons ────────────────│  Gmail API   │
│  Score &    │                                    │  Fetch Single│
│  Actions    │                                    │  Message     │
└─────────────┘                                    │  (format=raw)│
                                                   └──────────────┘
                                                          │
                                                          v
                                                   ┌──────────────┐
                                                   │  PhishNet    │
                                                   │  Analysis    │
                                                   │  Pipeline    │
                                                   └──────────────┘
```

### Technical Implementation

#### Incremental OAuth Flow
- **Scope**: `https://www.googleapis.com/auth/gmail.readonly` (requested on-demand)
- **Token Storage**: Short-lived access tokens, NO refresh tokens by default
- **Re-authentication**: User re-consents when token expires

#### Endpoints

##### 1. Request Check Endpoint
```http
POST /api/v2/on-demand/request-check
Headers: Cookie: session_jwt or Authorization: Bearer <jwt>
Body: { "messageId": "<gmail_message_id>" }

Response (No Token):
{
  "need_oauth": true,
  "oauth_url": "https://accounts.google.com/o/oauth2/auth?..."
}

Response (With Token):
{
  "score": 0.85,
  "risk_level": "HIGH",
  "reasons": ["Suspicious link detected", "Unknown sender"],
  "indicators": [...],
  "processing_time_ms": 150
}
```

##### 2. Incremental Auth Endpoint
```http
GET /api/v2/on-demand/auth/gmail
Redirect to Google OAuth with gmail.readonly scope
```

##### 3. Callback Endpoint
```http
GET /api/v2/on-demand/auth/callback?code=...
Exchange code for access token, store in session, return to frontend
```

#### Data Flow
1. **User Action**: Clicks "Check this email" in Gmail (via extension/add-on) or dashboard
2. **Frontend Request**: Sends `POST /api/v2/on-demand/request-check` with `messageId`
3. **Backend Check**: 
   - Validates user session (JWT)
   - Checks if valid Google access token exists
   - If NO token → return `{need_oauth: true, oauth_url: "..."}`
   - If YES → proceed to fetch
4. **OAuth Flow** (if needed):
   - Frontend redirects user to `oauth_url`
   - User consents to `gmail.readonly`
   - Google redirects to callback with code
   - Backend exchanges code for access token
   - Token stored in session (encrypted, short-lived)
   - Frontend retries check request
5. **Message Fetch**:
   - Backend calls `GET https://gmail.googleapis.com/gmail/v1/users/me/messages/{messageId}?format=raw`
   - Decodes base64 raw email content
   - Parses MIME message
6. **Analysis**:
   - Passes parsed email to PhishNet analysis pipeline
   - Generates threat score and indicators
7. **Response**:
   - Returns analysis results to frontend
   - **Does NOT store raw email** unless user consents
8. **User Consent** (optional):
   - Frontend shows: "Save this report to my account? ☐"
   - If checked → Backend persists analysis + metadata
   - If unchecked → Analysis discarded after response

#### Privacy & Security Features

##### Minimal Scopes
- Only request `gmail.readonly` when user initiates check
- No profile or email scopes unless needed

##### Short-Lived Tokens
- Access tokens valid for 1 hour
- **No refresh tokens** stored by default
- User re-authenticates when token expires

##### Data Minimization
- **Default**: Store only `{userId, messageId, score, timestamp}` (no raw email)
- **With Consent**: Store raw email + analysis for user's review
- **Auto-Delete**: Clear stored raw emails after 30 days (configurable)

##### Audit & Transparency
- Every fetch logged: `userId, messageId, timestamp, action`
- User can view audit log of all checked emails
- User can delete any stored email or entire history

##### Rate Limiting
- Per-user limit: 50 checks per hour (configurable)
- Global limit: 1000 checks per hour
- CAPTCHA trigger: 10 failed checks in 5 minutes

### Configuration

```env
# On-Demand Mode Settings
ONDEMAND_ACCESS_TOKEN_LIFETIME=3600  # 1 hour
ONDEMAND_STORE_REFRESH_TOKENS=false  # Privacy-first
ONDEMAND_DEFAULT_CONSENT=false       # Opt-in for storage
ONDEMAND_RETENTION_DAYS=30           # Auto-delete consented data

# Rate Limiting
ONDEMAND_USER_RATE_LIMIT=50         # Per hour
ONDEMAND_GLOBAL_RATE_LIMIT=1000     # Per hour
ONDEMAND_CAPTCHA_THRESHOLD=10       # Failed checks before CAPTCHA

# Scopes
GMAIL_ONDEMAND_SCOPES=https://www.googleapis.com/auth/gmail.readonly
```

---

## 🔄 Mode Comparison

| Feature | Bulk Forward (IMAP) | On-Demand (Gmail API) |
|---------|---------------------|------------------------|
| **User Action** | Forward all emails | Click "Check this" |
| **Scope** | Full IMAP access | gmail.readonly (minimal) |
| **OAuth** | Not required | Incremental, on-demand |
| **Data Storage** | Full emails stored | Metadata only (default) |
| **Privacy** | Lower (all emails shared) | Higher (user controls each share) |
| **UX** | Automatic, passive | Manual, per-email |
| **Use Case** | Comprehensive monitoring | Targeted, privacy-first |
| **Retention** | 90 days default | 30 days with consent |
| **Google Verification** | Easier (no Gmail API) | Requires privacy policy & review |

---

## 🔐 Security Considerations

### Both Modes
- ✅ TLS everywhere (HTTPS)
- ✅ Encrypted tokens at rest (AES-256)
- ✅ KMS for encryption keys
- ✅ Rate limiting and abuse detection
- ✅ Audit logging
- ✅ User data export and deletion

### Mode 1 (IMAP) Specific
- ⚠️ IMAP credentials stored securely
- ⚠️ Full email content stored (encryption at rest)
- ⚠️ Retention policy enforced

### Mode 2 (On-Demand) Specific
- ✅ No refresh tokens (privacy-first)
- ✅ Short-lived access tokens
- ✅ Incremental consent
- ✅ Minimal data storage by default
- ✅ User-controlled deletion
- ✅ Transparent audit trail

---

## 📊 Implementation Roadmap

### Phase 1: Backend API (Current Sprint)
- [x] Mode 1: IMAP integration (`QuickIMAPService`)
- [ ] Mode 2: On-demand check endpoint
- [ ] Incremental OAuth flow
- [ ] Message fetching with format=raw
- [ ] Consent management

### Phase 2: Frontend UI
- [ ] Mode selection UI
- [ ] "Check this email" button (Gmail Add-on/Extension)
- [ ] Consent modal
- [ ] Results display
- [ ] Audit log viewer

### Phase 3: Privacy & Compliance
- [ ] Privacy policy documentation
- [ ] Data export endpoints
- [ ] Delete endpoints
- [ ] Retention policies
- [ ] Google OAuth verification

### Phase 4: Testing & Monitoring
- [ ] Functional tests for both modes
- [ ] Security tests
- [ ] Performance tests
- [ ] Monitoring dashboards
- [ ] Abuse detection

---

## 📖 User Documentation

### For Users: Choosing a Mode

**Choose Bulk Forward Mode if:**
- You want automatic protection for all emails
- You trust PhishNet with full email access
- You work in an organization with centralized email security
- You prefer "set it and forget it" convenience

**Choose On-Demand Mode if:**
- You value privacy and want to control what you share
- You only need occasional phishing checks
- You're concerned about data storage and retention
- You want to keep emails in your own Gmail account

### Getting Started with Mode 1 (Bulk Forward)
1. Create a Gmail filter to forward suspicious emails
2. Set forward address to `phishnet@example.com`
3. All forwarded emails appear in PhishNet dashboard

### Getting Started with Mode 2 (On-Demand)
1. Install PhishNet Gmail Add-on or Chrome Extension
2. Open a suspicious email in Gmail
3. Click "Check with PhishNet" button
4. Consent to `gmail.readonly` (first time only)
5. View results and choose to save or discard

---

## 🔧 Developer Guide

### Adding Mode 2 Endpoints

```python
# backend/app/api/v2/on_demand.py

from fastapi import APIRouter, Depends, HTTPException, Request
from app.services.gmail_ondemand import GmailOnDemandService
from app.core.auth import get_current_user

router = APIRouter(prefix="/on-demand", tags=["On-Demand Check"])

@router.post("/request-check")
async def request_check(
    request: Request,
    payload: dict,
    current_user = Depends(get_current_user)
):
    """Request on-demand email check."""
    service = GmailOnDemandService()
    return await service.check_email(current_user, payload["messageId"])
```

### Implementing Incremental OAuth

```python
# backend/app/services/gmail_ondemand.py

class GmailOnDemandService:
    def __init__(self):
        self.scopes = ["https://www.googleapis.com/auth/gmail.readonly"]
    
    async def get_incremental_auth_url(self, user_id: str) -> str:
        """Generate incremental OAuth URL."""
        state = generate_state_token(user_id)
        return build_oauth_url(
            scopes=self.scopes,
            state=state,
            access_type="online",  # No refresh token
            prompt="consent"
        )
    
    async def fetch_message(self, user_id: str, message_id: str) -> dict:
        """Fetch single message using Gmail API."""
        token = await get_access_token(user_id)
        if not token:
            raise NeedOAuthException()
        
        # Fetch message with format=raw
        response = await gmail_api_call(
            f"/gmail/v1/users/me/messages/{message_id}?format=raw",
            token
        )
        
        # Decode and parse
        raw_bytes = base64.urlsafe_b64decode(response["raw"])
        email_message = email.message_from_bytes(raw_bytes)
        
        return email_message
```

---

## 📚 References

- [Gmail API Documentation](https://developers.google.com/gmail/api)
- [Incremental Authorization](https://developers.google.com/identity/protocols/oauth2/web-server#incrementalAuth)
- [OAuth 2.0 Scopes](https://developers.google.com/gmail/api/auth/scopes)
- [IMAP Protocol](https://www.rfc-editor.org/rfc/rfc3501)

---

## 🎯 Success Metrics

### Mode 1 (Bulk Forward)
- **Throughput**: 1000+ emails/minute
- **Latency**: <5 seconds from forward to analysis
- **Accuracy**: 95%+ threat detection

### Mode 2 (On-Demand)
- **Latency**: <2 seconds from request to response
- **Privacy Compliance**: 0 unauthorized access incidents
- **User Satisfaction**: 90%+ users prefer on-demand for privacy

---

**Last Updated**: 2025-11-03  
**Version**: 1.0  
**Author**: PhishNet Security Team
