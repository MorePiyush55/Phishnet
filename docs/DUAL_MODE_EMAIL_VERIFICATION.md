# PhishNet Dual-Mode Email Verification System

## Overview

PhishNet now supports **two ways** to verify your emails, giving you complete control over your privacy and security preferences:

### Option 1: Full Email Monitoring
Forward all your emails to the PhishNet dashboard for automatic verification and scoring.

### Option 2: On-Demand Verification (Recommended ⭐)
Privacy-focused approach where you only share specific suspicious emails with PhishNet.

---

## Quick Start

### For Privacy-Conscious Users (Option 2 - Recommended)

1. **Initial Setup**
   ```bash
   POST /api/v1/email-verification/initialize
   {
     "user_id": "your_user_id",
     "email": "you@example.com",
     "verification_mode": "on_demand"
   }
   ```

2. **When You See a Suspicious Email**
   
   Click "Check with PhishNet" button in your email client:
   
   ```bash
   # Frontend initiates OAuth if needed
   GET /api/v1/oauth/initiate?user_id=your_user_id
   
   # After OAuth, check the email
   POST /api/v1/email-verification/check
   {
     "user_id": "your_user_id",
     "gmail_message_id": "message_id_from_gmail",
     "user_initiated": true
   }
   ```

3. **View Results**
   ```json
   {
     "success": true,
     "analysis": {
       "threat_level": "HIGH",
       "confidence_score": 0.85,
       "detected_threats": [
         "Suspicious subject keyword: urgent",
         "Possible domain spoofing: paypal"
       ],
       "recommendation": "⚠️ HIGH RISK: This email shows strong phishing indicators..."
     },
     "privacy": {
       "raw_email_stored": false,
       "scheduled_deletion": "2025-12-03T10:30:00Z"
     }
   }
   ```

---

## Architecture

### Option 2: On-Demand Flow (Privacy-Focused)

```
┌─────────────┐
│   User      │
│   Gmail     │
└──────┬──────┘
       │
       │ 1. Sees suspicious email
       │
       ▼
┌─────────────────────┐
│  PhishNet Frontend  │
│  "Check with        │
│   PhishNet" button  │
└──────┬──────────────┘
       │
       │ 2. Click triggers OAuth (if needed)
       │
       ▼
┌─────────────────────┐
│  Incremental OAuth  │
│  (gmail.readonly)   │
└──────┬──────────────┘
       │
       │ 3. User grants permission
       │
       ▼
┌─────────────────────┐
│  Backend API        │
│  /check endpoint    │
└──────┬──────────────┘
       │
       │ 4. Fetch ONLY that message (by ID)
       │
       ▼
┌─────────────────────┐
│  Gmail API          │
│  GET message/{id}   │
└──────┬──────────────┘
       │
       │ 5. Raw email data
       │
       ▼
┌─────────────────────┐
│  Analysis Engine    │
│  Phishing Detection │
└──────┬──────────────┘
       │
       │ 6. Store metadata only (default)
       │    or full email if consented
       │
       ▼
┌─────────────────────┐
│  MongoDB            │
│  + Privacy Settings │
└──────┬──────────────┘
       │
       │ 7. Return results
       │
       ▼
┌─────────────────────┐
│  Frontend           │
│  Display risk score │
│  + recommendation   │
└─────────────────────┘
       │
       │ 8. Auto-delete per retention policy
       │
       ▼
   [Deleted]
```

---

## API Reference

### Privacy Settings Management

#### Initialize User Privacy Settings
```http
POST /api/v1/email-verification/initialize
Content-Type: application/json

{
  "user_id": "string",
  "email": "user@example.com",
  "verification_mode": "on_demand"
}
```

**Response:**
```json
{
  "user_id": "user_123",
  "email": "user@example.com",
  "verification_mode": "on_demand",
  "consents": {
    "gmail_read": false,
    "store_raw_email": false,
    "store_metadata": true,
    "auto_analysis": false,
    "share_threat_intel": true
  },
  "retention_policy": "retain_30_days",
  "rate_limits": {
    "max_checks_per_hour": 20,
    "max_checks_per_day": 100
  }
}
```

#### Get Privacy Settings
```http
GET /api/v1/email-verification/settings/{user_id}
```

#### Update Verification Mode
```http
POST /api/v1/email-verification/mode/update
Content-Type: application/json

{
  "user_id": "user_123",
  "mode": "on_demand"
}
```

**Available Modes:**
- `on_demand` - Check only specific emails (privacy-focused) ⭐
- `full_monitoring` - Check all emails automatically
- `hybrid` - Combination of both

### Consent Management

#### Grant/Revoke Consent
```http
POST /api/v1/email-verification/consent/grant
Content-Type: application/json

{
  "user_id": "user_123",
  "consent_type": "gmail_read",
  "granted": true
}
```

**Consent Types:**
- `gmail_read` - Read Gmail messages (required)
- `store_raw_email` - Store complete email content
- `store_metadata` - Store email metadata only (default: true)
- `auto_analysis` - Automatic analysis of forwarded emails
- `share_threat_intel` - Share anonymized threat data

### Email Verification

#### Check Specific Email (Option 2)
```http
POST /api/v1/email-verification/check
Content-Type: application/json

{
  "user_id": "user_123",
  "gmail_message_id": "msg_abc123xyz",
  "user_initiated": true
}
```

**Response:**
```json
{
  "success": true,
  "request_id": "req_xyz789",
  "analysis": {
    "id": "analysis_456",
    "threat_level": "HIGH",
    "confidence_score": 0.85,
    "detected_threats": [
      "Suspicious subject keyword: urgent",
      "Possible domain spoofing: paypal",
      "URL shortener detected: bit.ly"
    ],
    "suspicious_links": [
      "http://bit.ly/suspicious123"
    ],
    "recommendation": "⚠️ HIGH RISK: This email shows strong phishing indicators. Be extremely cautious. Verify sender independently before taking any action."
  },
  "privacy": {
    "raw_email_stored": false,
    "scheduled_deletion": "2025-12-03T10:30:00Z"
  }
}
```

**Error Response (OAuth Required):**
```json
{
  "success": false,
  "error": "gmail_read_consent_required",
  "message": "User must grant Gmail read permission",
  "oauth_required": true
}
```

#### Get Analysis History
```http
GET /api/v1/email-verification/history/{user_id}?limit=50&offset=0
```

### OAuth Management

#### Initiate Incremental OAuth
```http
GET /api/v1/oauth/initiate
  ?user_id=user_123
  &scope=gmail.readonly
  &return_url=https://yourapp.com/dashboard
```

**Response:**
```json
{
  "auth_url": "https://accounts.google.com/o/oauth2/v2/auth?client_id=...",
  "state": "random_state_token",
  "expires_in": 600
}
```

#### OAuth Callback
```http
GET /api/v1/oauth/callback?code=auth_code&state=state_token
```

#### Check OAuth Status
```http
GET /api/v1/oauth/status/{user_id}
```

**Response:**
```json
{
  "user_id": "user_123",
  "connected": true,
  "has_access_token": true,
  "token_valid": true,
  "token_expires_at": "2025-11-04T10:30:00Z",
  "gmail_read_consent": true,
  "requires_oauth": false
}
```

#### Revoke OAuth
```http
POST /api/v1/oauth/revoke?user_id=user_123
```

### Data Retention

#### Update Retention Policy
```http
POST /api/v1/email-verification/retention/update
Content-Type: application/json

{
  "user_id": "user_123",
  "retention_policy": "retain_7_days"
}
```

**Retention Policies:**
- `delete_immediately` - Delete right after analysis
- `retain_7_days` - Keep for 7 days
- `retain_30_days` - Keep for 30 days (default)
- `retain_90_days` - Keep for 90 days
- `retain_indefinitely` - Keep forever (requires explicit consent)

### Rate Limiting

#### Check Rate Limit Status
```http
GET /api/v1/email-verification/rate-limit/{user_id}
```

**Response:**
```json
{
  "within_limits": true,
  "message": "Rate limit OK",
  "limits": {
    "hourly": {
      "used": 5,
      "max": 20,
      "remaining": 15
    },
    "daily": {
      "used": 23,
      "max": 100,
      "remaining": 77
    }
  }
}
```

---

## Privacy Features

### 🔒 What Makes Option 2 Private?

1. **Minimal Permissions**
   - Only `gmail.readonly` scope requested
   - No write or modify permissions
   - Can't send emails or change settings

2. **Incremental Authorization**
   - Permissions requested only when needed
   - User explicitly clicks "Check with PhishNet"
   - No background scanning

3. **Data Minimization**
   - By default, only metadata stored (sender, subject, date)
   - Raw email content NOT stored unless you consent
   - Analysis happens in-memory

4. **Configurable Retention**
   - Choose how long data is kept
   - Auto-deletion after retention period
   - Delete anytime via API

5. **Granular Consent**
   - Separate consent for each data type
   - Audit trail of all consent changes
   - Revoke anytime

6. **Rate Limiting**
   - Prevents abuse
   - Default: 20/hour, 100/day
   - Customizable per user

7. **Audit Logging**
   - Every action logged
   - IP address and user agent tracked
   - GDPR-compliant audit trail

---

## Security Features

### 🛡️ How We Protect Your Data

1. **Encrypted Tokens**
   - OAuth tokens encrypted at rest
   - AES-256 encryption
   - Keys rotated regularly

2. **HTTPS Only**
   - All API calls over TLS
   - Certificate pinning recommended
   - No unencrypted transmission

3. **Short-lived Tokens**
   - Access tokens expire in 1 hour
   - Refresh tokens optional
   - Can operate without stored refresh tokens

4. **Message ID Only**
   - Frontend sends only message ID
   - Backend fetches from Gmail
   - User can't be spoofed

5. **CSRF Protection**
   - State tokens for OAuth flow
   - Expires in 10 minutes
   - Single-use only

6. **Input Validation**
   - All inputs validated
   - Rate limiting enforced
   - SQL injection protection (MongoDB)

---

## Privacy Policy Requirements

### For Google OAuth Verification

Your privacy policy MUST include:

1. **What Data We Collect**
   - Gmail message ID
   - Email metadata (sender, subject, date)
   - Raw email content (only if consented)
   - Analysis results

2. **How We Use It**
   - Phishing detection and analysis
   - Threat intelligence (anonymized)
   - Service improvement

3. **How Long We Keep It**
   - Based on user's retention policy
   - Default: 30 days
   - Auto-deletion after period

4. **User Rights**
   - Access your data anytime
   - Delete your data anytime
   - Export your data
   - Revoke permissions anytime

5. **Third-Party Sharing**
   - No sharing of raw emails
   - Anonymized threat intel only
   - User consent required

---

## Testing

### Test On-Demand Flow

```bash
# 1. Initialize privacy settings
curl -X POST http://localhost:8000/api/v1/email-verification/initialize \
  -H "Content-Type: application/json" \
  -d '{
    "user_id": "test_user",
    "email": "test@example.com",
    "verification_mode": "on_demand"
  }'

# 2. Initiate OAuth
curl http://localhost:8000/api/v1/oauth/initiate?user_id=test_user

# 3. After OAuth, check email
curl -X POST http://localhost:8000/api/v1/email-verification/check \
  -H "Content-Type: application/json" \
  -d '{
    "user_id": "test_user",
    "gmail_message_id": "msg123",
    "user_initiated": true
  }'

# 4. View history
curl http://localhost:8000/api/v1/email-verification/history/test_user?limit=10
```

---

## Frontend Integration

### React Example

```jsx
import React, { useState } from 'react';

const EmailCheckButton = ({ messageId, userId }) => {
  const [checking, setChecking] = useState(false);
  const [result, setResult] = useState(null);

  const checkEmail = async () => {
    setChecking(true);
    
    try {
      // Check OAuth status first
      const statusRes = await fetch(`/api/v1/oauth/status/${userId}`);
      const status = await statusRes.json();
      
      if (status.requires_oauth) {
        // Initiate OAuth
        const oauthRes = await fetch(`/api/v1/oauth/initiate?user_id=${userId}`);
        const oauth = await oauthRes.json();
        
        // Redirect to Google OAuth
        window.location.href = oauth.auth_url;
        return;
      }
      
      // Check email
      const checkRes = await fetch('/api/v1/email-verification/check', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          user_id: userId,
          gmail_message_id: messageId,
          user_initiated: true
        })
      });
      
      const data = await checkRes.json();
      setResult(data);
      
    } catch (error) {
      console.error('Error checking email:', error);
    } finally {
      setChecking(false);
    }
  };

  return (
    <div>
      <button onClick={checkEmail} disabled={checking}>
        {checking ? 'Checking...' : '🔍 Check with PhishNet'}
      </button>
      
      {result && result.success && (
        <div className={`alert alert-${result.analysis.threat_level}`}>
          <h4>Threat Level: {result.analysis.threat_level}</h4>
          <p>Confidence: {(result.analysis.confidence_score * 100).toFixed(0)}%</p>
          <p>{result.analysis.recommendation}</p>
          
          {result.analysis.detected_threats.length > 0 && (
            <ul>
              {result.analysis.detected_threats.map((threat, i) => (
                <li key={i}>{threat}</li>
              ))}
            </ul>
          )}
          
          <small>
            Data will be deleted: {result.privacy.scheduled_deletion}
          </small>
        </div>
      )}
    </div>
  );
};

export default EmailCheckButton;
```

---

## Comparison: Option 1 vs Option 2

| Feature | Option 1: Full Monitoring | Option 2: On-Demand ⭐ |
|---------|--------------------------|------------------------|
| **Privacy** | Low - All emails shared | High - Only selected emails |
| **Control** | Automatic | Full user control |
| **OAuth Scope** | Broad, persistent | Minimal, just-in-time |
| **Token Storage** | Refresh tokens required | Short-lived access tokens |
| **Data Stored** | All emails by default | Metadata only by default |
| **User Action** | None required | Click to check |
| **Convenience** | High | Medium |
| **GDPR Compliance** | Challenging | Easy |
| **Google Verification** | Difficult | Easier |
| **Best For** | Organizations | Individual users |

---

## Troubleshooting

### "OAuth Required" Error
```json
{
  "success": false,
  "error": "gmail_read_consent_required",
  "oauth_required": true
}
```
**Solution:** Initiate OAuth flow with `/api/v1/oauth/initiate`

### "Rate Limit Exceeded"
```json
{
  "success": false,
  "error": "rate_limit_exceeded",
  "message": "Hourly rate limit exceeded (20/20)"
}
```
**Solution:** Wait until next hour or contact admin to increase limits

### "Invalid Token"
```json
{
  "success": false,
  "error": "invalid_token",
  "oauth_required": true
}
```
**Solution:** Token expired. Re-initiate OAuth flow.

---

## Next Steps

1. **Configure OAuth Credentials**
   ```bash
   export GMAIL_CLIENT_ID="your_client_id"
   export GMAIL_CLIENT_SECRET="your_client_secret"
   export GMAIL_REDIRECT_URI="http://localhost:8000/api/v1/oauth/callback"
   ```

2. **Start Backend**
   ```bash
   cd backend
   python main.py
   ```

3. **Test Endpoints**
   - Visit `http://localhost:8000/docs` for interactive API docs
   - Test OAuth flow
   - Try checking an email

4. **Integrate Frontend**
   - Add "Check with PhishNet" button
   - Handle OAuth redirect
   - Display results

---

## Support

For questions or issues:
- API Documentation: `http://localhost:8000/docs`
- Email: support@phishnet.com
- GitHub Issues: https://github.com/yourrepo/phishnet

---

## License

MIT License - See LICENSE file for details
