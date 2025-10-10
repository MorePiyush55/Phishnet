# Render Environment Configuration for PhishNet

## OAuth Environment Variables

To complete the OAuth setup, you need to configure these environment variables in your Render dashboard:

### Required Environment Variables

1. **Go to Render Dashboard**
   - Visit: https://dashboard.render.com/
   - Select your PhishNet backend service
   - Go to "Environment" tab

2. **Add these Environment Variables:**

```bash
# Google OAuth Credentials (from Google Cloud Console)
GMAIL_CLIENT_ID=your_google_client_id_here
GMAIL_CLIENT_SECRET=your_google_client_secret_here

# OAuth Configuration
GMAIL_REDIRECT_URI=https://phishnet-backend-iuoc.onrender.com/api/v1/auth/gmail/callback

# Frontend URL (for OAuth redirects)
FRONTEND_URL=https://phishnet-tau.vercel.app

# Base URL (for callback URL generation)
BASE_URL=https://phishnet-backend-iuoc.onrender.com
```

### How to Get Google OAuth Credentials

1. **Google Cloud Console**
   - Visit: https://console.cloud.google.com/
   - Select your project (or create a new one)

2. **Enable APIs**
   - APIs & Services → Library
   - Enable "Gmail API"
   - Enable "Google+ API" (if available)

3. **Create OAuth Credentials**
   - APIs & Services → Credentials
   - Click "Create Credentials" → "OAuth 2.0 Client IDs"
   - Application type: "Web application"
   - Name: "PhishNet OAuth Client"

4. **Configure Authorized URIs**
   - **Authorized JavaScript origins:**
     ```
     https://phishnet-backend-iuoc.onrender.com
     https://phishnet-tau.vercel.app
     ```
   
   - **Authorized redirect URIs:**
     ```
     https://phishnet-backend-iuoc.onrender.com/api/v1/auth/gmail/callback
     https://phishnet-backend-iuoc.onrender.com/api/test/oauth/callback
     ```

5. **Get Credentials**
   - Copy the "Client ID" → Use as `GMAIL_CLIENT_ID`
   - Copy the "Client secret" → Use as `GMAIL_CLIENT_SECRET`

### Testing OAuth Flow

After setting environment variables:

1. **Redeploy backend** (Render will auto-redeploy after env var changes)
2. **Test OAuth endpoint:** https://phishnet-backend-iuoc.onrender.com/api/test/oauth
3. **Complete flow:** Should redirect to frontend successfully after Google login

### Troubleshooting

**Common Issues:**

1. **"missing_credentials" error**
   - Check that `GMAIL_CLIENT_ID` and `GMAIL_CLIENT_SECRET` are set in Render
   - Verify they're copied correctly from Google Cloud Console

2. **"token_exchange_failed" error**
   - Verify redirect URIs in Google Cloud Console match your backend URL
   - Check that Gmail API is enabled in Google Cloud Console

3. **"invalid_client" error**
   - Double-check client ID and secret are correct
   - Ensure OAuth consent screen is properly configured

### Security Notes

- Never commit OAuth credentials to git
- Use environment variables only
- Regularly rotate OAuth secrets
- Monitor OAuth usage in Google Cloud Console

### Verification

To verify environment variables are loaded:
- Check Render deployment logs for "client_id exists: true"
- Visit `/health` endpoint to see if OAuth is configured
- Test OAuth flow end-to-end