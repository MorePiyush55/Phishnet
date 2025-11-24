# PhishNet Dual-Mode Email Verification - Verification Checklist

## ✅ Pre-Deployment Checklist

Use this checklist to verify your PhishNet dual-mode email verification system is ready.

---

## 🔧 Configuration

### OAuth Credentials
- [ ] Google Cloud Project created
- [ ] Gmail API enabled
- [ ] OAuth 2.0 Client ID created (Web application)
- [ ] Redirect URI configured: `http://localhost:8000/api/v1/oauth/callback`
- [ ] Production redirect URI configured (if deploying)
- [ ] `GMAIL_CLIENT_ID` set in `.env`
- [ ] `GMAIL_CLIENT_SECRET` set in `.env`
- [ ] `GMAIL_REDIRECT_URI` set in `.env`

### Database
- [ ] MongoDB installed and running
- [ ] MongoDB connection string in `.env`
- [ ] Database `phishnet` created
- [ ] Collections can be created (permissions OK)

### Environment Variables
```bash
# Required
- [ ] GMAIL_CLIENT_ID
- [ ] GMAIL_CLIENT_SECRET
- [ ] GMAIL_REDIRECT_URI
- [ ] MONGODB_URI

# Recommended
- [ ] SECRET_KEY (for session management)
- [ ] CORS_ORIGINS (for frontend)
```

---

## 🗂️ Files Created

### Models
- [ ] `backend/app/models/privacy_consent.py` exists
- [ ] Contains `UserPrivacySettings` class
- [ ] Contains `EmailCheckRequest` class
- [ ] Contains `ConsentAuditLog` class
- [ ] Contains `DataDeletionRequest` class
- [ ] Contains all enums (EmailVerificationMode, ConsentType, etc.)

### Services
- [ ] `backend/app/services/email_verification_service.py` exists
- [ ] Contains `EmailVerificationService` class
- [ ] All methods implemented

### API Endpoints
- [ ] `backend/app/api/v1/email_verification.py` exists
- [ ] All endpoints defined (initialize, check, settings, etc.)
- [ ] `backend/app/api/v1/oauth_incremental.py` exists
- [ ] OAuth flow endpoints defined (initiate, callback, status, revoke)

### Integration
- [ ] Privacy models added to `mongodb_models.py`
- [ ] Routers registered in `main.py`
- [ ] No import errors when starting server

### Documentation
- [ ] `docs/DUAL_MODE_EMAIL_VERIFICATION.md` created
- [ ] `docs/IMPLEMENTATION_GUIDE.md` created
- [ ] `DUAL_MODE_QUICKSTART.md` created
- [ ] `IMPLEMENTATION_SUMMARY.md` created
- [ ] `demo_frontend.html` created

---

## 🧪 Functional Testing

### Backend Startup
```bash
cd backend
python main.py
```

- [ ] Server starts without errors
- [ ] MongoDB connection successful
- [ ] No router loading errors
- [ ] Health endpoint responds: `curl http://localhost:8000/health`

### API Accessibility
Test these endpoints:

```bash
# Health check
curl http://localhost:8000/health
- [ ] Returns 200 OK

# API docs
curl http://localhost:8000/docs
- [ ] Opens in browser

# Verification modes
curl http://localhost:8000/api/v1/email-verification/modes
- [ ] Returns list of modes

# Consent types
curl http://localhost:8000/api/v1/email-verification/consent-types
- [ ] Returns list of consent types

# System info
curl http://localhost:8000/api/v1/email-verification/info
- [ ] Returns system information

# OAuth config
curl http://localhost:8000/api/v1/oauth/config
- [ ] Returns OAuth configuration
```

### User Initialization
```bash
curl -X POST http://localhost:8000/api/v1/email-verification/initialize \
  -H "Content-Type: application/json" \
  -d '{
    "user_id": "test_user_checklist",
    "email": "test@example.com",
    "verification_mode": "on_demand"
  }'
```

- [ ] Returns 200 OK
- [ ] Response contains user_id, email, verification_mode
- [ ] Response contains consents dictionary
- [ ] Response contains retention_policy
- [ ] Response contains rate_limits

### Get Settings
```bash
curl http://localhost:8000/api/v1/email-verification/settings/test_user_checklist
```

- [ ] Returns 200 OK
- [ ] Returns previously initialized settings

### OAuth Initiation
```bash
curl "http://localhost:8000/api/v1/oauth/initiate?user_id=test_user_checklist"
```

- [ ] Returns 200 OK
- [ ] Response contains auth_url
- [ ] Response contains state token
- [ ] auth_url starts with `https://accounts.google.com/`

### OAuth Callback (Manual Test)
- [ ] Visit auth_url from previous step
- [ ] Google OAuth consent screen appears
- [ ] Can grant permissions
- [ ] Redirects back to callback URL
- [ ] No errors in callback processing

### Check OAuth Status
```bash
curl http://localhost:8000/api/v1/oauth/status/test_user_checklist
```

- [ ] Returns 200 OK
- [ ] Response shows connection status
- [ ] `requires_oauth` field present

### Email Check (After OAuth)
```bash
# This will only work after OAuth is completed
curl -X POST http://localhost:8000/api/v1/email-verification/check \
  -H "Content-Type: application/json" \
  -d '{
    "user_id": "test_user_checklist",
    "gmail_message_id": "test_message_id",
    "user_initiated": true
  }'
```

Expected outcomes:
- [ ] If OAuth not done: Returns error with `oauth_required: true`
- [ ] If OAuth done but invalid message ID: Returns error
- [ ] If valid: Returns analysis results

### Rate Limiting
```bash
curl http://localhost:8000/api/v1/email-verification/rate-limit/test_user_checklist
```

- [ ] Returns 200 OK
- [ ] Shows hourly and daily limits
- [ ] Shows current usage

---

## 🎨 Frontend Testing

### Demo Frontend
- [ ] Open `demo_frontend.html` in browser
- [ ] Page loads without errors
- [ ] Can see both mode cards
- [ ] "Option 2: On-Demand" marked as recommended
- [ ] Form fields present (API Base URL, User ID, Message ID)
- [ ] Buttons present (Initialize, Connect Gmail, Check Email)

### Demo Workflow
1. **Initialize User**
   - [ ] Click "1️⃣ Initialize User"
   - [ ] Enter email when prompted
   - [ ] Success message appears
   - [ ] "2️⃣ Connect Gmail" button enables

2. **Connect Gmail**
   - [ ] Click "2️⃣ Connect Gmail"
   - [ ] Redirects to Google OAuth
   - [ ] Can grant permissions
   - [ ] Redirects back to demo page
   - [ ] Status shows "Gmail Connected ✓"
   - [ ] "3️⃣ Check Email" button enables

3. **Check Email** (Requires real Gmail message ID)
   - [ ] Enter Gmail message ID
   - [ ] Click "3️⃣ Check Email"
   - [ ] Loading spinner appears
   - [ ] Result box appears with analysis
   - [ ] Threat level displayed
   - [ ] Confidence score shown
   - [ ] Recommendation provided

---

## 🔐 Security Verification

### OAuth Security
- [ ] State token generated for CSRF protection
- [ ] State token has expiration (10 minutes)
- [ ] State token is single-use
- [ ] Redirect URI matches configured value exactly
- [ ] Client secret NOT exposed in frontend
- [ ] Access tokens encrypted at rest (if stored)

### API Security
- [ ] HTTPS enabled (in production)
- [ ] CORS configured correctly
- [ ] Rate limiting active
- [ ] Input validation on all endpoints
- [ ] Error messages don't leak sensitive info

### Data Privacy
- [ ] Raw email NOT stored by default
- [ ] Metadata storage requires consent
- [ ] Data retention policy enforced
- [ ] Audit logging enabled
- [ ] User can revoke consent
- [ ] User can delete data

---

## 📊 Database Verification

Connect to MongoDB and check:

```bash
mongosh phishnet
```

```javascript
// Check collections created
show collections

// Should see (after running tests):
// - user_privacy_settings
// - email_check_requests
// - consent_audit_logs
// - users (if users created)
// - email_analyses (if emails checked)

// Check user privacy settings
db.user_privacy_settings.find().pretty()
- [ ] Contains test user
- [ ] verification_mode set correctly
- [ ] consents object present
- [ ] retention_policy set

// Check audit logs
db.consent_audit_logs.find().pretty()
- [ ] Logs created for consent changes
- [ ] Timestamps present
- [ ] User ID tracked

// Check indexes
db.user_privacy_settings.getIndexes()
- [ ] Index on user_id exists (unique)
- [ ] Index on email exists
```

---

## 📚 Documentation Verification

- [ ] `DUAL_MODE_QUICKSTART.md` readable and accurate
- [ ] `IMPLEMENTATION_SUMMARY.md` complete
- [ ] `docs/DUAL_MODE_EMAIL_VERIFICATION.md` comprehensive
- [ ] `docs/IMPLEMENTATION_GUIDE.md` has step-by-step instructions
- [ ] API documentation at `/docs` complete and accurate
- [ ] Code comments present and helpful
- [ ] README updated with new features

---

## 🚀 Production Readiness

### Environment
- [ ] Production `.env` configured
- [ ] Production MongoDB URI set
- [ ] Production OAuth credentials set
- [ ] Production redirect URI in Google Cloud Console
- [ ] HTTPS/SSL certificate configured
- [ ] CORS set to production domains only

### Privacy & Legal
- [ ] Privacy policy page created
- [ ] Terms of service page created
- [ ] Privacy policy linked in OAuth consent screen
- [ ] Data retention policy documented
- [ ] User rights (access, delete, export) documented
- [ ] GDPR compliance verified

### Monitoring
- [ ] Logging configured
- [ ] Error tracking set up
- [ ] Metrics collection enabled
- [ ] Health check endpoint monitored
- [ ] Rate limit monitoring active
- [ ] Database performance monitored

### Backup & Recovery
- [ ] MongoDB backup strategy defined
- [ ] Disaster recovery plan documented
- [ ] OAuth token recovery process defined
- [ ] User data export functionality tested

---

## 🎯 User Acceptance Testing

### For Privacy-Conscious Users (Option 2)
- [ ] Can initialize with `on_demand` mode
- [ ] Can see suspicious email in client
- [ ] Can click "Check with PhishNet"
- [ ] OAuth flow completes successfully
- [ ] Email analysis shows threat level
- [ ] Results displayed clearly
- [ ] Can view analysis history
- [ ] Can change retention policy
- [ ] Can revoke OAuth access
- [ ] Can delete their data

### For Organizations (Option 1)
- [ ] Can initialize with `full_monitoring` mode
- [ ] Can set up email forwarding
- [ ] All emails automatically analyzed
- [ ] Dashboard shows all threats
- [ ] Can export analysis reports
- [ ] Historical data retained per policy

---

## 🐛 Edge Cases Tested

- [ ] User without OAuth tries to check email → Shows oauth_required
- [ ] Invalid message ID → Returns appropriate error
- [ ] Expired access token → Refreshes automatically or requests re-auth
- [ ] Rate limit exceeded → Returns rate limit error
- [ ] Invalid user ID → Returns 404
- [ ] Malformed request → Returns 400 with clear message
- [ ] MongoDB connection lost → Returns 503
- [ ] Gmail API timeout → Returns appropriate error

---

## 📈 Performance Checks

- [ ] Email check completes in < 5 seconds
- [ ] OAuth flow completes in < 30 seconds
- [ ] API endpoints respond in < 500ms
- [ ] Database queries use indexes
- [ ] No memory leaks after 100 requests
- [ ] Rate limiting doesn't block legitimate use

---

## ✅ Final Verification

### Quick Test Script
```bash
#!/bin/bash

echo "🧪 Testing PhishNet Dual-Mode Email Verification"

# 1. Health check
echo "\n1️⃣ Health Check..."
curl -s http://localhost:8000/health | jq

# 2. Get modes
echo "\n2️⃣ Verification Modes..."
curl -s http://localhost:8000/api/v1/email-verification/modes | jq

# 3. Initialize user
echo "\n3️⃣ Initialize User..."
curl -s -X POST http://localhost:8000/api/v1/email-verification/initialize \
  -H "Content-Type: application/json" \
  -d '{
    "user_id": "final_test_user",
    "email": "final_test@example.com",
    "verification_mode": "on_demand"
  }' | jq

# 4. Get settings
echo "\n4️⃣ Get Settings..."
curl -s http://localhost:8000/api/v1/email-verification/settings/final_test_user | jq

# 5. Check OAuth config
echo "\n5️⃣ OAuth Config..."
curl -s http://localhost:8000/api/v1/oauth/config | jq

# 6. System info
echo "\n6️⃣ System Info..."
curl -s http://localhost:8000/api/v1/email-verification/info | jq

echo "\n✅ All tests completed!"
```

Save as `test_phishnet.sh` and run:
```bash
chmod +x test_phishnet.sh
./test_phishnet.sh
```

- [ ] All tests pass
- [ ] All responses are valid JSON
- [ ] No error messages

---

## 🎉 Ready for Deployment!

If all checkboxes are checked, your PhishNet dual-mode email verification system is ready!

### Next Steps:
1. ✅ Deploy to production
2. ✅ Submit for Google OAuth verification
3. ✅ Monitor usage and performance
4. ✅ Gather user feedback
5. ✅ Iterate and improve

---

## 📞 Support

If any tests fail:

1. **Check Logs**
   ```bash
   tail -f backend/logs/app.log
   ```

2. **Check MongoDB**
   ```bash
   mongosh phishnet
   db.serverStatus()
   ```

3. **Check Environment**
   ```bash
   echo $GMAIL_CLIENT_ID
   echo $MONGODB_URI
   ```

4. **Review Documentation**
   - `DUAL_MODE_QUICKSTART.md`
   - `docs/IMPLEMENTATION_GUIDE.md`
   - `http://localhost:8000/docs`

---

**Date:** _______________
**Tester:** _______________
**Status:** ☐ All Tests Pass ☐ Issues Found

**Notes:**
_______________________________________
_______________________________________
_______________________________________
