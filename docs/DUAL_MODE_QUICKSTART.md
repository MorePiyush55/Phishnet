# PhishNet Dual-Mode Quick Start

## 🚀 Get Started in 5 Minutes

### Choose Your Mode

**Privacy-conscious?** → Use **Mode 2: On-Demand Check**  
**Want full protection?** → Use **Mode 1: Bulk Forward**

---

## Mode 1: Bulk Forward (IMAP)

### Setup (One-time, 2 minutes)

1. **Configure PhishNet IMAP inbox**:
   ```env
   # In your .env file
   IMAP_HOST=imap.gmail.com
   IMAP_PORT=993
   IMAP_EMAIL=phishnet@yourdomain.com
   IMAP_PASSWORD=your-app-password
   ```

2. **Forward emails from Gmail**:
   - Gmail Settings → Forwarding
   - Add forwarding address: `phishnet@yourdomain.com`
   - Confirm forwarding

3. **View results**:
   ```
   http://localhost:8000/dashboard
   ```

✅ **Done!** All forwarded emails will be automatically analyzed.

---

## Mode 2: On-Demand Check (Gmail API) ⭐ RECOMMENDED

### Setup (One-time, 3 minutes)

1. **Configure Google OAuth**:
   ```env
   # In your .env file
   GMAIL_CLIENT_ID=your_client_id.apps.googleusercontent.com
   GMAIL_CLIENT_SECRET=your_client_secret
   BASE_URL=http://localhost:8000
   FRONTEND_URL=http://localhost:5173
   ```

2. **Get OAuth credentials**:
   - Go to [Google Cloud Console](https://console.cloud.google.com)
   - Create OAuth 2.0 credentials
   - Add redirect URI: `http://localhost:8000/api/v2/on-demand/auth/callback`

3. **Start backend**:
   ```bash
   cd backend
   python -m app.main
   ```

4. **Open browser and authenticate**:
   ```
   http://localhost:8000/api/v2/on-demand/auth/gmail
   ```

✅ **Done!** You can now check individual emails on-demand.

---

## Using Mode 2: Check an Email

### Method 1: API Call

```bash
# Get your JWT token first (login)
TOKEN="your_jwt_token"

# Check an email
curl -X POST http://localhost:8000/api/v2/on-demand/request-check \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "message_id": "18c5a2b3d4e5f6g7",
    "store_consent": false
  }'
```

### Method 2: Frontend Integration

```javascript
// Add this to your frontend
async function checkEmail(messageId) {
  const response = await fetch('/api/v2/on-demand/request-check', {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${userToken}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({
      message_id: messageId,
      store_consent: false
    })
  });
  
  const result = await response.json();
  
  if (result.need_oauth) {
    // User needs to authenticate
    window.location.href = result.oauth_url;
  } else {
    // Show analysis results
    console.log('Threat Score:', result.analysis.score);
    console.log('Risk Level:', result.analysis.risk_level);
  }
}
```

---

## Privacy Features

### View Your Audit Log

```bash
curl -X GET http://localhost:8000/api/v2/on-demand/audit-log \
  -H "Authorization: Bearer $TOKEN"
```

### Delete Your Data

```bash
# Delete all stored analyses
curl -X DELETE http://localhost:8000/api/v2/on-demand/delete \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"delete_all": true}'
```

### Export Your Data (GDPR)

```bash
curl -X GET http://localhost:8000/api/v2/on-demand/export-data \
  -H "Authorization: Bearer $TOKEN" \
  > my-phishnet-data.json
```

---

## Comparison

| Feature | Mode 1 (Bulk) | Mode 2 (On-Demand) |
|---------|---------------|---------------------|
| **Setup Time** | 2 minutes | 3 minutes |
| **User Action** | None (automatic) | Click per email |
| **OAuth Required** | No | Yes (minimal scope) |
| **Data Storage** | All emails | None (by default) |
| **Privacy** | Medium | **High** ⭐ |
| **Best For** | Organizations | Individuals |

---

## Next Steps

- **Full Documentation**: [DUAL_MODE_IMPLEMENTATION_GUIDE.md](./DUAL_MODE_IMPLEMENTATION_GUIDE.md)
- **Architecture**: [docs/DUAL_MODE_EMAIL_ARCHITECTURE.md](./docs/DUAL_MODE_EMAIL_ARCHITECTURE.md)
- **Privacy Policy**: [docs/PRIVACY_POLICY.md](./docs/PRIVACY_POLICY.md)

---

## Troubleshooting

### "Need OAuth" Response?
- Click the returned `oauth_url` to authenticate
- This is normal for first-time use

### Token Expired?
- Re-authenticate (no refresh token by design for privacy)
- Tokens last 1 hour

### Message Not Found?
- Verify the message ID from Gmail
- Ensure you have access to the message

---

**🎉 You're all set!** Start checking emails securely.
