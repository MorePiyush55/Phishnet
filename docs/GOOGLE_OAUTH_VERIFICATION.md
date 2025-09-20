# Google OAuth App Verification Guide

## Current Status
✅ OAuth flow is working correctly
⚠️ App shows "unverified" warning (normal for development)

## Quick Solutions

### 1. For Testing (Immediate)
**Add test users to Google Cloud Console:**

1. Go to: https://console.cloud.google.com
2. Select your project
3. Navigate: APIs & Services > OAuth consent screen
4. Scroll to "Test users" section
5. Click "ADD USERS"
6. Add email addresses: propam5553@gmail.com (and other testers)
7. Save

**Test users will NOT see the warning!**

### 2. For Development (Current)
**Users can safely proceed by:**
1. Click "Hide Advanced" (if visible)
2. Click "Go to phishnet-backend-iuoc.onrender.com (unsafe)"
3. Continue with OAuth flow

### 3. For Production (Future)
**To remove warning completely, Google requires:**

#### Required Information:
- ✅ App name: PhishNet
- ✅ User support email: propam5553@gmail.com
- ✅ Developer contact: propam5553@gmail.com
- ✅ Authorized domains: onrender.com, vercel.app

#### Required Pages (Create these):
- 🔲 Privacy Policy URL
- 🔲 Terms of Service URL
- 🔲 App Homepage URL

#### Verification Process:
1. Complete OAuth consent screen
2. Submit verification request
3. Google security review (2-6 weeks)
4. App becomes "verified"

## Current OAuth Scopes
- `openid` - Basic OAuth
- `email` - User email address
- `profile` - Basic profile info
- `https://www.googleapis.com/auth/gmail.readonly` - Read Gmail (sensitive scope)

## Next Steps

### Immediate (Testing):
1. Add test users to Google Cloud Console
2. Test OAuth flow with added users
3. No verification warning for test users

### Short-term (MVP):
1. Keep current setup for development
2. Add security notice on frontend (already done)
3. Continue building features

### Long-term (Production):
1. Create privacy policy page
2. Create terms of service page
3. Submit for Google verification
4. Remove "unverified" warning

## Security Notes
- OAuth 2.0 provides security even for "unverified" apps
- Google controls all authentication
- Your app never sees user passwords
- Users can revoke access anytime
- Read-only access only (cannot modify/delete emails)

## Current Configuration
- Client ID: 830148817247-7kog97nrhe2ve3i8n8cvj0mrts0icj2q.apps.googleusercontent.com
- Redirect URI: https://phishnet-backend-iuoc.onrender.com/api/test/oauth/callback
- Status: Working correctly, shows expected warning