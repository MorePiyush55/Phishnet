# PhishNet Dual-Mode Implementation Guide

## 🎯 Quick Start

PhishNet now supports **two modes** for email verification:

### Mode 1: Bulk Forward (IMAP) - "Forward All"
- **What it does**: Automatically scans ALL emails forwarded to PhishNet
- **Use case**: Organizations wanting comprehensive email protection
- **Privacy**: Medium (all forwarded emails stored)

### Mode 2: On-Demand Check (Gmail API) - "Check This"
- **What it does**: User clicks a button to check ONE suspicious email
- **Use case**: Privacy-conscious individuals
- **Privacy**: High (minimal data storage, user controlled)

---

## 🚀 Backend Implementation Complete

### ✅ What's Been Implemented

#### 1. **On-Demand Email Check Service**
**File**: `backend/app/services/gmail_ondemand.py`

Key features:
- Fetch single Gmail message using Message ID
- Incremental OAuth (gmail.readonly scope only)
- Short-lived tokens (no refresh tokens by default)
- Privacy-first: No storage without consent

```python
# Example usage
from app.services.gmail_ondemand import gmail_ondemand_service

result = await gmail_ondemand_service.check_email_on_demand(
    user_id="user123",
    message_id="18c5a2b3d4e5f6g7",
    access_token="ya29.a0...",
    store_consent=False  # Don't store unless user consents
)
```

#### 2. **On-Demand API Endpoints**
**File**: `backend/app/api/v2/on_demand.py`

Endpoints available:
- `POST /api/v2/on-demand/request-check` - Check single email
- `GET /api/v2/on-demand/auth/gmail` - Start incremental OAuth
- `GET /api/v2/on-demand/auth/callback` - OAuth callback
- `GET /api/v2/on-demand/history` - View stored analyses
- `DELETE /api/v2/on-demand/delete` - Delete stored data
- `GET /api/v2/on-demand/audit-log` - View audit trail
- `GET /api/v2/on-demand/export-data` - Export all data (GDPR)

#### 3. **MongoDB Models**
**File**: `backend/app/models/mongodb_models.py`

New collections:
- `OAuthCredentials` - Encrypted token storage
- `OnDemandAnalysis` - Privacy-first analysis storage

#### 4. **Documentation**
**File**: `docs/DUAL_MODE_EMAIL_ARCHITECTURE.md`

Complete architecture documentation with:
- Mode comparison
- UX flows
- Privacy considerations
- Security checklist

---

## 📱 Frontend Integration Guide

### Step 1: Check if User Needs OAuth

```javascript
// Check email on-demand
async function checkEmail(messageId) {
  const response = await fetch('/api/v2/on-demand/request-check', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${userToken}`
    },
    body: JSON.stringify({
      message_id: messageId,
      store_consent: false  // User can choose later
    })
  });
  
  const result = await response.json();
  
  if (result.need_oauth) {
    // Redirect to OAuth
    window.location.href = result.oauth_url;
  } else {
    // Display analysis results
    displayAnalysis(result);
  }
}
```

### Step 2: Handle OAuth Callback

```javascript
// In your OAuth callback page
const urlParams = new URLSearchParams(window.location.search);

if (urlParams.get('oauth_success') === 'true') {
  // OAuth successful, retry the check
  const pendingMessageId = localStorage.getItem('pending_check_message_id');
  if (pendingMessageId) {
    checkEmail(pendingMessageId);
    localStorage.removeItem('pending_check_message_id');
  }
} else if (urlParams.get('oauth_error')) {
  // Handle OAuth error
  alert(`OAuth failed: ${urlParams.get('oauth_error')}`);
}
```

### Step 3: Display Results with Consent Option

```javascript
function displayAnalysis(result) {
  // Show threat score and analysis
  const threatLevel = result.analysis.risk_level;
  const score = result.analysis.score;
  
  // Show consent modal
  const saveData = confirm(
    `Threat Score: ${score}\n` +
    `Risk Level: ${threatLevel}\n\n` +
    `Would you like to save this analysis to your account?\n` +
    `(Without saving, this analysis will not be stored)`
  );
  
  if (saveData) {
    // Re-run check with consent
    recheckWithConsent(result.message_id);
  }
}
```

---

## 🎨 React Component Example

```jsx
// OnDemandEmailCheck.jsx
import React, { useState } from 'react';

export function OnDemandEmailCheck({ messageId, onClose }) {
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [showConsentModal, setShowConsentModal] = useState(false);

  const checkEmail = async (storeConsent = false) => {
    setLoading(true);
    
    try {
      const response = await fetch('/api/v2/on-demand/request-check', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${localStorage.getItem('access_token')}`
        },
        body: JSON.stringify({
          message_id: messageId,
          store_consent: storeConsent
        })
      });
      
      const data = await response.json();
      
      if (data.need_oauth) {
        // Store message ID for retry after OAuth
        localStorage.setItem('pending_check_message_id', messageId);
        // Redirect to OAuth
        window.location.href = data.oauth_url;
      } else {
        setResult(data);
        if (!storeConsent) {
          setShowConsentModal(true);
        }
      }
    } catch (error) {
      alert('Failed to check email: ' + error.message);
    } finally {
      setLoading(false);
    }
  };

  const handleSaveConsent = () => {
    setShowConsentModal(false);
    checkEmail(true);  // Re-check with consent
  };

  return (
    <div className="on-demand-check-modal">
      <h2>Check This Email</h2>
      
      {loading && <div>Analyzing email...</div>}
      
      {result && (
        <div className="analysis-results">
          <div className={`threat-badge threat-${result.analysis.risk_level.toLowerCase()}`}>
            {result.analysis.risk_level}
          </div>
          <div className="threat-score">
            Score: {(result.analysis.score * 100).toFixed(0)}%
          </div>
          
          <h3>Indicators</h3>
          <ul>
            {result.analysis.indicators.map((indicator, i) => (
              <li key={i}>{indicator}</li>
            ))}
          </ul>
          
          <h3>Recommendations</h3>
          <ul>
            {result.analysis.recommendations.map((rec, i) => (
              <li key={i}>{rec}</li>
            ))}
          </ul>
          
          {showConsentModal && (
            <div className="consent-modal">
              <p>
                ℹ️ This analysis was performed on-demand and is not stored.
              </p>
              <p>
                Would you like to save this report to your account for future reference?
              </p>
              <button onClick={handleSaveConsent}>Save Report</button>
              <button onClick={() => setShowConsentModal(false)}>
                Don't Save
              </button>
              <p className="privacy-note">
                If you choose not to save, this analysis will be deleted immediately.
              </p>
            </div>
          )}
        </div>
      )}
      
      <button onClick={() => checkEmail(false)} disabled={loading}>
        {loading ? 'Checking...' : 'Check Email'}
      </button>
      <button onClick={onClose}>Close</button>
    </div>
  );
}
```

---

## 🔒 Privacy & Security Features

### Data Storage

#### Default (No Consent)
- ✅ Analysis performed
- ✅ Results returned to user
- ❌ No raw email stored
- ❌ No analysis stored
- ✅ Audit log entry (metadata only)

#### With Consent
- ✅ Analysis performed
- ✅ Results returned to user
- ✅ Metadata stored (sender, subject, score)
- ✅ Full analysis stored
- ✅ Raw email stored (optional)
- ✅ Auto-delete after 30 days

### Token Management

- **Access Token**: 1 hour lifetime
- **Refresh Token**: NOT stored (privacy-first)
- **Re-authentication**: Required when token expires
- **Encryption**: AES-256 for stored tokens

### User Rights

- ✅ View audit log (all checked emails)
- ✅ View stored analyses
- ✅ Delete specific analyses
- ✅ Delete all data
- ✅ Export all data (GDPR compliance)

---

## 🧪 Testing Your Implementation

### Test Endpoints

```bash
# 1. Start OAuth flow
curl -X GET http://localhost:8000/api/v2/on-demand/auth/gmail \
  -H "Authorization: Bearer YOUR_JWT_TOKEN"

# 2. Check email (with valid token)
curl -X POST http://localhost:8000/api/v2/on-demand/request-check \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"message_id": "18c5a2b3d4e5f6g7", "store_consent": false}'

# 3. View history
curl -X GET http://localhost:8000/api/v2/on-demand/history \
  -H "Authorization: Bearer YOUR_JWT_TOKEN"

# 4. View audit log
curl -X GET http://localhost:8000/api/v2/on-demand/audit-log \
  -H "Authorization: Bearer YOUR_JWT_TOKEN"

# 5. Delete data
curl -X DELETE http://localhost:8000/api/v2/on-demand/delete \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"delete_all": true}'
```

---

## 🎯 Next Steps

### For Frontend Developers

1. **Create UI component** for "Check this email" button
2. **Add consent modal** for data storage
3. **Implement OAuth flow** handling
4. **Add analysis results display**
5. **Create audit log viewer**

### For Backend Developers

1. **Add rate limiting** (currently not enforced)
2. **Implement CAPTCHA** for abuse prevention
3. **Add retention policy** auto-deletion job
4. **Setup monitoring** for OAuth flow
5. **Add comprehensive tests**

### For DevOps

1. **Setup environment variables**:
   ```env
   GMAIL_CLIENT_ID=your_client_id
   GMAIL_CLIENT_SECRET=your_client_secret
   BASE_URL=https://your-backend.com
   FRONTEND_URL=https://your-frontend.com
   ENCRYPTION_KEY=32-byte-key-for-token-encryption
   ```

2. **Configure MongoDB collections**:
   - Collections auto-created on first use
   - Indexes auto-created

3. **Setup cron job** for retention policy:
   ```python
   # Delete expired analyses
   await OnDemandAnalysis.find({
       "retention_until": {"$lt": datetime.now(timezone.utc)}
   }).delete()
   ```

---

## 📖 API Documentation

Full API documentation available at:
- Interactive docs: `http://localhost:8000/docs`
- Architecture: `docs/DUAL_MODE_EMAIL_ARCHITECTURE.md`

---

## 🆘 Troubleshooting

### "Need OAuth" Response
- **Cause**: No valid access token found
- **Solution**: Redirect user to returned `oauth_url`

### "Token Expired"
- **Cause**: Access token lifetime (1 hour) exceeded
- **Solution**: Re-authenticate (no refresh token by design)

### "Message Not Found"
- **Cause**: Invalid message ID or user doesn't have access
- **Solution**: Verify message ID from Gmail

### OAuth Redirect Mismatch
- **Cause**: `BASE_URL` environment variable doesn't match deployed URL
- **Solution**: Update `BASE_URL` to match your deployment

---

## 📝 Privacy Policy Template

For Google OAuth verification, you'll need a privacy policy. Here's a template:

```markdown
## Data Collection and Use

### Mode 1: Bulk Forward
When you forward emails to PhishNet:
- We store full email content for analysis
- Data retained for 90 days (configurable)
- You can delete data anytime

### Mode 2: On-Demand Check
When you use "Check this email":
- We fetch only the email you select
- By default, we DO NOT store the email
- If you consent, we store metadata for 30 days
- You can delete data anytime

### Your Rights
- View all stored data
- Delete specific emails or all data
- Export all data (GDPR)
- Revoke OAuth access anytime
```

---

## ✅ Checklist for Production

- [ ] Set strong `JWT_SECRET` and `ENCRYPTION_KEY`
- [ ] Configure `GMAIL_CLIENT_ID` and `GMAIL_CLIENT_SECRET`
- [ ] Update `BASE_URL` and `FRONTEND_URL`
- [ ] Enable HTTPS/TLS
- [ ] Add rate limiting middleware
- [ ] Implement CAPTCHA for abuse prevention
- [ ] Setup retention policy cron job
- [ ] Create privacy policy page
- [ ] Test OAuth flow end-to-end
- [ ] Submit Google OAuth verification (if needed)
- [ ] Setup monitoring and alerting
- [ ] Add comprehensive tests

---

**🎉 Implementation Status: Backend Complete!**

Frontend UI and additional security features are next steps.
