# PhishNet OAuth Setup Guide

## Overview

PhishNet uses Google OAuth 2.0 for user authentication and Gmail API access.

---

## Quick Setup

### Step 1: Create Google Cloud Project

1. Go to https://console.cloud.google.com
2. Create new project → Name: "PhishNet"
3. Enable APIs:
   - Gmail API
   - Google+ API (for profile info)

### Step 2: Configure OAuth Consent Screen

1. Go to **APIs & Services** → **OAuth consent screen**
2. Select **External** user type
3. Fill in:
   - App name: `PhishNet`
   - User support email: Your email
   - Developer contact: Your email
4. Add scopes:
   - `openid`
   - `email`
   - `profile`
   - `gmail.readonly` (optional, for Gmail API)
5. Add test users (for development)

### Step 3: Create OAuth Credentials

1. Go to **APIs & Services** → **Credentials**
2. Click **Create Credentials** → **OAuth client ID**
3. Application type: **Web application**
4. Name: `PhishNet Web Client`
5. Authorized JavaScript origins:
   ```
   http://localhost:3000
   http://localhost:5173
   https://phishnet-tau.vercel.app
   ```
6. Authorized redirect URIs:
   ```
   http://localhost:8000/api/v1/auth/gmail/callback
   https://phishnet-backend-iuoc.onrender.com/api/v1/auth/gmail/callback
   ```
7. Click **Create**
8. Copy **Client ID** and **Client Secret**

### Step 4: Configure Environment Variables

Add to Render environment:

```env
GMAIL_CLIENT_ID=your-client-id.apps.googleusercontent.com
GMAIL_CLIENT_SECRET=GOCSPX-your-secret
GMAIL_REDIRECT_URI=https://phishnet-backend-iuoc.onrender.com/api/v1/auth/gmail/callback
```

---

## OAuth Flow

```
User                    Frontend                  Backend                   Google
  │                        │                         │                         │
  │  Click "Sign in"       │                         │                         │
  │───────────────────────>│                         │                         │
  │                        │  Redirect to Google     │                         │
  │                        │─────────────────────────────────────────────────>│
  │                        │                         │                         │
  │                        │                         │  User authenticates     │
  │<───────────────────────────────────────────────────────────────────────────│
  │                        │                         │                         │
  │                        │  Callback with code     │                         │
  │                        │<─────────────────────────────────────────────────│
  │                        │                         │                         │
  │                        │  Exchange code          │                         │
  │                        │────────────────────────>│  Get tokens from Google │
  │                        │                         │────────────────────────>│
  │                        │                         │<────────────────────────│
  │                        │                         │                         │
  │                        │  Return JWT             │                         │
  │                        │<────────────────────────│                         │
  │                        │                         │                         │
  │  Authenticated!        │                         │                         │
  │<───────────────────────│                         │                         │
```

---

## API Endpoints

### Initiate OAuth
```http
GET /api/v1/auth/gmail/authorize
```
Returns Google OAuth authorization URL.

### OAuth Callback
```http
GET /api/v1/auth/gmail/callback?code={auth_code}&state={state}
```
Exchanges authorization code for tokens.

### Token Refresh
```http
POST /api/v1/auth/refresh
Content-Type: application/json

{
  "refresh_token": "your-refresh-token"
}
```

---

## Gmail API Scopes

| Scope | Purpose | Required |
|-------|---------|----------|
| `openid` | OpenID Connect | Yes |
| `email` | Get user email | Yes |
| `profile` | Get user name/photo | Yes |
| `gmail.readonly` | Read emails | Optional |
| `gmail.modify` | Mark emails as read | Optional |

---

## Best Practices

### Token Storage
- Store access tokens in memory (frontend)
- Store refresh tokens securely (httpOnly cookies or encrypted storage)
- Never expose tokens in URLs or logs

### Token Refresh
- Access tokens expire in 1 hour
- Refresh tokens automatically before expiry
- Handle refresh failures gracefully

### Rate Limiting
- Gmail API: 250 quota units/user/second
- Implement exponential backoff for 429 errors
- Cache frequently accessed data

### Security
- Validate `state` parameter to prevent CSRF
- Use HTTPS for all OAuth communication
- Limit scopes to minimum required

---

## Troubleshooting

### "Access blocked: App not verified"
- Add test users in OAuth consent screen
- Or submit for Google verification

### "Invalid redirect URI"
- Ensure exact match in Google Console
- Check for trailing slashes
- Verify correct environment (dev vs prod)

### "Invalid client"
- Check Client ID is correct
- Verify Client Secret matches
- Ensure credentials are for correct project

### Token refresh fails
- Check refresh token is valid
- Verify `GMAIL_CLIENT_SECRET` is correct
- User may have revoked access

---

## Google Verification (Production)

For production apps with 100+ users:

1. Complete OAuth consent screen with:
   - Privacy policy URL
   - Terms of service URL
   - Logo and branding
   - Detailed scope justification

2. Submit for verification at:
   https://support.google.com/cloud/answer/9110914

3. Wait 4-6 weeks for review

4. Provide demo video if requested
