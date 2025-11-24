# PhishNet Dual-Mode Implementation Guide

## Quick Implementation Checklist

### ✅ Backend Setup (Completed)

- [x] Privacy consent models created (`app/models/privacy_consent.py`)
- [x] Email verification service implemented (`app/services/email_verification_service.py`)
- [x] API endpoints created (`app/api/v1/email_verification.py`)
- [x] Incremental OAuth flow (`app/api/v1/oauth_incremental.py`)
- [x] MongoDB models updated
- [x] Routers registered in `main.py`

### 🔧 Configuration Required

1. **Set OAuth Credentials**

   Create or update `.env` file:
   ```bash
   GMAIL_CLIENT_ID=your_client_id_here
   GMAIL_CLIENT_SECRET=your_client_secret_here
   GMAIL_REDIRECT_URI=http://localhost:8000/api/v1/oauth/callback
   
   # Production
   # GMAIL_REDIRECT_URI=https://yourdomain.com/api/v1/oauth/callback
   ```

2. **Get OAuth Credentials from Google**
   
   a. Go to [Google Cloud Console](https://console.cloud.google.com/)
   
   b. Create a new project or select existing
   
   c. Enable Gmail API
   
   d. Create OAuth 2.0 Client ID (Web application)
   
   e. Add authorized redirect URIs:
      - `http://localhost:8000/api/v1/oauth/callback` (dev)
      - `https://yourdomain.com/api/v1/oauth/callback` (prod)
   
   f. Copy Client ID and Client Secret to `.env`

3. **MongoDB Connection**
   
   Ensure MongoDB is running and connected:
   ```bash
   MONGODB_URI=mongodb://localhost:27017/phishnet
   ```

### 🚀 Running the System

1. **Start Backend**
   ```bash
   cd backend
   python main.py
   ```

2. **Verify API is Running**
   ```bash
   curl http://localhost:8000/health
   ```

3. **Check API Documentation**
   
   Open browser: `http://localhost:8000/docs`

### 🧪 Testing the Implementation

#### Test 1: Initialize User Privacy Settings

```bash
curl -X POST http://localhost:8000/api/v1/email-verification/initialize \
  -H "Content-Type: application/json" \
  -d '{
    "user_id": "test_user_123",
    "email": "test@example.com",
    "verification_mode": "on_demand"
  }'
```

Expected response:
```json
{
  "user_id": "test_user_123",
  "email": "test@example.com",
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

#### Test 2: Get Available Verification Modes

```bash
curl http://localhost:8000/api/v1/email-verification/modes
```

#### Test 3: Initiate OAuth Flow

```bash
curl "http://localhost:8000/api/v1/oauth/initiate?user_id=test_user_123"
```

Expected response:
```json
{
  "auth_url": "https://accounts.google.com/o/oauth2/v2/auth?client_id=...",
  "state": "random_state_token",
  "expires_in": 600
}
```

#### Test 4: Check OAuth Configuration

```bash
curl http://localhost:8000/api/v1/oauth/config
```

### 📱 Frontend Integration

#### Basic HTML + JavaScript Example

```html
<!DOCTYPE html>
<html>
<head>
    <title>PhishNet Email Checker</title>
    <style>
        .check-button {
            background: #4CAF50;
            color: white;
            padding: 10px 20px;
            border: none;
            border-radius: 5px;
            cursor: pointer;
        }
        .result {
            margin-top: 20px;
            padding: 15px;
            border-radius: 5px;
        }
        .result.safe { background: #d4edda; }
        .result.low { background: #fff3cd; }
        .result.medium { background: #f8d7da; }
        .result.high { background: #f5c6cb; }
        .result.critical { background: #f5c6cb; border: 2px solid red; }
    </style>
</head>
<body>
    <h1>PhishNet Email Checker</h1>
    
    <div>
        <label>Gmail Message ID:</label>
        <input type="text" id="messageId" placeholder="Enter message ID">
        <button class="check-button" onclick="checkEmail()">
            🔍 Check with PhishNet
        </button>
    </div>
    
    <div id="result"></div>
    
    <script>
        const API_BASE = 'http://localhost:8000';
        const USER_ID = 'test_user_123'; // In production, get from auth
        
        async function checkEmail() {
            const messageId = document.getElementById('messageId').value;
            if (!messageId) {
                alert('Please enter a message ID');
                return;
            }
            
            const resultDiv = document.getElementById('result');
            resultDiv.innerHTML = 'Checking...';
            
            try {
                // Check OAuth status
                const statusRes = await fetch(`${API_BASE}/api/v1/oauth/status/${USER_ID}`);
                const status = await statusRes.json();
                
                if (status.requires_oauth) {
                    // Need OAuth - initiate flow
                    const oauthRes = await fetch(
                        `${API_BASE}/api/v1/oauth/initiate?user_id=${USER_ID}&return_url=${window.location.href}`
                    );
                    const oauth = await oauthRes.json();
                    
                    // Redirect to Google
                    window.location.href = oauth.auth_url;
                    return;
                }
                
                // Check email
                const checkRes = await fetch(`${API_BASE}/api/v1/email-verification/check`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        user_id: USER_ID,
                        gmail_message_id: messageId,
                        user_initiated: true
                    })
                });
                
                const result = await checkRes.json();
                
                if (result.success) {
                    displayResult(result.analysis);
                } else {
                    resultDiv.innerHTML = `
                        <div class="result" style="background: #f8d7da;">
                            <strong>Error:</strong> ${result.message || result.error}
                        </div>
                    `;
                }
                
            } catch (error) {
                resultDiv.innerHTML = `
                    <div class="result" style="background: #f8d7da;">
                        <strong>Error:</strong> ${error.message}
                    </div>
                `;
            }
        }
        
        function displayResult(analysis) {
            const resultDiv = document.getElementById('result');
            const level = (analysis.threat_level || 'safe').toLowerCase();
            
            resultDiv.innerHTML = `
                <div class="result ${level}">
                    <h3>Analysis Result</h3>
                    <p><strong>Threat Level:</strong> ${analysis.threat_level || 'SAFE'}</p>
                    <p><strong>Confidence:</strong> ${(analysis.confidence_score * 100).toFixed(0)}%</p>
                    <p>${analysis.recommendation}</p>
                    
                    ${analysis.detected_threats && analysis.detected_threats.length > 0 ? `
                        <h4>Detected Threats:</h4>
                        <ul>
                            ${analysis.detected_threats.map(t => `<li>${t}</li>`).join('')}
                        </ul>
                    ` : ''}
                    
                    ${analysis.suspicious_links && analysis.suspicious_links.length > 0 ? `
                        <h4>Suspicious Links:</h4>
                        <ul>
                            ${analysis.suspicious_links.map(l => `<li>${l}</li>`).join('')}
                        </ul>
                    ` : ''}
                </div>
            `;
        }
        
        // Check for OAuth return
        const urlParams = new URLSearchParams(window.location.search);
        if (urlParams.get('oauth') === 'success') {
            alert('OAuth successful! You can now check emails.');
            // Clear URL params
            window.history.replaceState({}, document.title, window.location.pathname);
        }
    </script>
</body>
</html>
```

Save this as `test_frontend.html` and open in browser.

### 🎯 Integration Points

#### 1. Gmail Add-on (Chrome Extension)

Create a Chrome extension that adds a "Check with PhishNet" button to Gmail:

```javascript
// content.js
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === 'checkEmail') {
    const messageId = getGmailMessageId(); // Extract from Gmail DOM
    
    fetch('http://localhost:8000/api/v1/email-verification/check', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        user_id: getUserId(),
        gmail_message_id: messageId,
        user_initiated: true
      })
    })
    .then(res => res.json())
    .then(data => {
      displayPhishingWarning(data.analysis);
    });
  }
});
```

#### 2. Mobile App Integration

For React Native or Flutter apps:

```javascript
// PhishNetService.js
export class PhishNetService {
  static async checkEmail(userId, messageId) {
    const response = await fetch(`${API_BASE}/api/v1/email-verification/check`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        user_id: userId,
        gmail_message_id: messageId,
        user_initiated: true
      })
    });
    
    return await response.json();
  }
  
  static async initiateOAuth(userId) {
    const response = await fetch(`${API_BASE}/api/v1/oauth/initiate?user_id=${userId}`);
    const data = await response.json();
    
    // Open OAuth URL in browser
    Linking.openURL(data.auth_url);
  }
}
```

### 🔐 Security Checklist

- [ ] OAuth credentials stored securely (not in code)
- [ ] HTTPS enabled in production
- [ ] CORS configured for your domain
- [ ] Rate limiting enabled
- [ ] MongoDB authentication enabled
- [ ] Tokens encrypted at rest
- [ ] Audit logging enabled
- [ ] Privacy policy published
- [ ] Terms of service published

### 📊 Monitoring

#### Check System Health

```bash
# Backend health
curl http://localhost:8000/health

# API documentation
curl http://localhost:8000/docs

# Check database connection
curl http://localhost:8000/api/v1/email-verification/info
```

#### Monitor Rate Limits

```bash
curl http://localhost:8000/api/v1/email-verification/rate-limit/test_user_123
```

### 🐛 Common Issues

#### Issue 1: "OAuth not configured"

**Error:**
```json
{
  "detail": "OAuth not configured. Please set GMAIL_CLIENT_ID and GMAIL_CLIENT_SECRET"
}
```

**Solution:**
- Check `.env` file exists
- Verify `GMAIL_CLIENT_ID` and `GMAIL_CLIENT_SECRET` are set
- Restart backend server

#### Issue 2: "Invalid redirect URI"

**Error from Google:**
```
Error 400: redirect_uri_mismatch
```

**Solution:**
- Go to Google Cloud Console
- Add exact redirect URI to authorized URIs
- Match exactly including protocol (http/https) and port

#### Issue 3: "MongoDB connection failed"

**Error:**
```
RuntimeError: MongoDB is required for PhishNet to function
```

**Solution:**
```bash
# Start MongoDB
mongod --dbpath /path/to/data

# Or use Docker
docker run -d -p 27017:27017 --name mongodb mongo:latest
```

#### Issue 4: "Module not found"

**Error:**
```python
ImportError: cannot import name 'EmailVerificationService'
```

**Solution:**
```bash
# Ensure all files are created
cd backend
python -c "from app.services.email_verification_service import EmailVerificationService; print('OK')"

# If fails, check file paths and __init__.py files
```

### 🚢 Production Deployment

#### Environment Variables

```bash
# Production .env
GMAIL_CLIENT_ID=your_production_client_id
GMAIL_CLIENT_SECRET=your_production_client_secret
GMAIL_REDIRECT_URI=https://yourdomain.com/api/v1/oauth/callback

MONGODB_URI=mongodb://username:password@production-mongo:27017/phishnet?authSource=admin

# Security
SECRET_KEY=your_long_random_secret_key
CORS_ORIGINS=https://yourdomain.com,https://app.yourdomain.com

# Features
ENABLE_METRICS=true
GDPR_COMPLIANCE_ENABLED=true
```

#### Deploy to Render/Heroku

```bash
# Render.yaml already configured in backend/render.yaml

# Or manual deployment:
git push heroku main
```

### 📝 Next Steps

1. **Test the implementation locally**
2. **Integrate with your frontend**
3. **Set up Google OAuth credentials**
4. **Create privacy policy page**
5. **Submit for Google OAuth verification**
6. **Deploy to production**
7. **Monitor usage and errors**

### 📞 Support

If you encounter issues:

1. Check logs: `tail -f backend/logs/app.log`
2. Review API docs: `http://localhost:8000/docs`
3. Test individual endpoints with curl
4. Check MongoDB data: `mongosh phishnet`

### ✨ Features Completed

✅ Dual-mode email verification (Full Monitoring + On-Demand)
✅ Privacy-focused Option 2 (Recommended)
✅ Incremental OAuth flow
✅ Granular consent management
✅ Configurable data retention
✅ Rate limiting
✅ Audit logging
✅ GDPR compliance features
✅ Comprehensive API documentation
✅ Frontend integration examples

### 🎉 Ready to Use!

Your PhishNet system now supports both verification modes. Users can choose:

- **Option 1**: Forward all emails for automatic protection
- **Option 2**: Manually check suspicious emails (privacy-focused) ⭐

The system is production-ready with privacy and security best practices!
