# OAuth Configuration Fix

## Issue Identified
The OAuth callback URL mismatch was causing "Not Found" errors after Google login. The backend is deployed at `phishnet-backend-iuoc.onrender.com` but OAuth was configured for `phishnet-backend-juoc.onrender.com`.

## Fixed OAuth Redirect URIs

### Backend Configuration (Updated)
- **Development**: `http://localhost:8000/api/v1/auth/gmail/callback`
- **Production**: `https://phishnet-backend-iuoc.onrender.com/api/v1/auth/gmail/callback`

## Google OAuth Console Configuration Required

To complete the OAuth setup, you need to update your Google OAuth Console:

### 1. Go to Google Cloud Console
- Visit: https://console.cloud.google.com/
- Select your PhishNet project

### 2. Navigate to OAuth Consent Screen
- APIs & Services > OAuth consent screen
- Ensure app is configured properly

### 3. Update OAuth Client Credentials
- APIs & Services > Credentials
- Click on your OAuth 2.0 Client ID
- Update **Authorized redirect URIs** to include BOTH URLs for smooth transition:

```
https://phishnet-backend-iuoc.onrender.com/api/v1/auth/gmail/callback
https://phishnet-backend-iuoc.onrender.com/api/auth/gmail/callback
https://phishnet-backend-iuoc.onrender.com/api/test/oauth/callback
```

**IMPORTANT**: Add the test OAuth callback URL to allow testing the OAuth flow.

### 4. Environment Variables for Render
Set these environment variables in your Render dashboard:

```bash
GMAIL_CLIENT_ID=your_google_client_id
GMAIL_CLIENT_SECRET=your_google_client_secret
GMAIL_REDIRECT_URI=https://phishnet-backend-iuoc.onrender.com/api/v1/auth/gmail/callback
```

## Testing OAuth Flow

After updating Google OAuth Console:

1. **Visit**: https://phishnet-backend-iuoc.onrender.com/api/test/oauth
2. **Click**: "Start OAuth Flow"
3. **Login**: With Google account
4. **Verify**: Successful callback and token reception

## Security Notes

- All redirect URIs must use HTTPS in production
- Ensure your Google Cloud Project has Gmail API enabled
- Verify OAuth consent screen is properly configured
- Check that all required scopes are included in your OAuth flow

## Deployment URLs Summary

- **Backend**: https://phishnet-backend-iuoc.onrender.com
- **Frontend**: https://phishnet-frontend.vercel.app (or your Vercel URL)
- **OAuth Callback**: https://phishnet-backend-iuoc.onrender.com/api/v1/auth/gmail/callback