# 🔧 Fix OAuth "token_exchange_failed" Error

## 🚨 Current Issue
Your PhishNet backend is deployed and working, but the OAuth flow fails with `token_exchange_failed` because **Google OAuth credentials are missing** from the Render environment.

## ✅ **Step-by-Step Solution**

### **1. Check Current Configuration**
First, visit this URL to see what's missing:
```
https://phishnet-backend-iuoc.onrender.com/api/debug/oauth-config
```

This will show you which environment variables are missing.

### **2. Create Google OAuth Credentials**

#### **A. Go to Google Cloud Console**
1. Visit: https://console.cloud.google.com/
2. Select your project (or create a new one named "PhishNet")

#### **B. Enable Required APIs**
1. Go to **APIs & Services** → **Library**
2. Search and enable:
   - ✅ **Gmail API**
   - ✅ **Google+ API** (if available)

#### **C. Create OAuth 2.0 Credentials**
1. Go to **APIs & Services** → **Credentials**
2. Click **"Create Credentials"** → **"OAuth 2.0 Client IDs"**
3. Configure OAuth consent screen first if prompted:
   - User Type: **External**
   - App name: **PhishNet**
   - User support email: **your-email@gmail.com**
   - Developer contact: **your-email@gmail.com**

#### **D. Configure OAuth Client**
1. Application type: **Web application**
2. Name: **PhishNet Backend**
3. **Authorized JavaScript origins:**
   ```
   https://phishnet-backend-iuoc.onrender.com
   https://phishnet-tau.vercel.app
   ```
4. **Authorized redirect URIs:**
   ```
   https://phishnet-backend-iuoc.onrender.com/api/test/oauth/callback
   https://phishnet-backend-iuoc.onrender.com/api/v1/auth/gmail/callback
   https://phishnet-backend-iuoc.onrender.com/api/rest/auth/callback
   ```

#### **E. Get Your Credentials**
1. Click **"Create"**
2. Copy the **Client ID** (starts with something like `123456789-abc...googleusercontent.com`)
3. Copy the **Client Secret** (random string like `GOCSPX-abc123...`)

### **3. Add Environment Variables to Render**

#### **A. Go to Render Dashboard**
1. Visit: https://dashboard.render.com/
2. Find your **PhishNet backend service**
3. Click on the service name

#### **B. Add Environment Variables**
1. Go to **"Environment"** tab
2. Click **"Add Environment Variable"**
3. Add these variables **one by one**:

```bash
# Google OAuth Credentials
GMAIL_CLIENT_ID=YOUR_CLIENT_ID_FROM_GOOGLE
GMAIL_CLIENT_SECRET=YOUR_CLIENT_SECRET_FROM_GOOGLE

# OAuth Configuration
GMAIL_REDIRECT_URI=https://phishnet-backend-iuoc.onrender.com/api/v1/auth/gmail/callback

# Frontend URL
FRONTEND_URL=https://phishnet-tau.vercel.app

# Base URL
BASE_URL=https://phishnet-backend-iuoc.onrender.com
```

#### **C. Save and Redeploy**
1. After adding all variables, Render will automatically redeploy
2. Wait for the deployment to complete (2-3 minutes)

### **4. Test the OAuth Flow**

#### **A. Check Configuration**
Visit: `https://phishnet-backend-iuoc.onrender.com/api/debug/oauth-config`

You should see:
```json
{
  "oauth_configuration": {
    "gmail_client_id_configured": true,
    "gmail_client_secret_configured": true,
    "gmail_redirect_uri": "https://phishnet-backend-iuoc.onrender.com/api/v1/auth/gmail/callback",
    "frontend_url": "https://phishnet-tau.vercel.app",
    "base_url": "https://phishnet-backend-iuoc.onrender.com"
  }
}
```

#### **B. Test OAuth Flow**
1. Visit: `https://phishnet-backend-iuoc.onrender.com/api/rest/auth/google`
2. Click through Google authorization
3. Should redirect to: `https://phishnet-tau.vercel.app/?oauth_success=true&email=your@email.com`

## 🎉 **Expected Result**
After completing these steps:
- ✅ OAuth flow completes successfully
- ✅ No more `token_exchange_failed` error
- ✅ User logs into PhishNet dashboard
- ✅ Full application functionality

## 🆘 **If You Still Have Issues**

1. **Check Render logs:** Go to Render dashboard → Your service → Logs tab
2. **Verify credentials:** Use the debug endpoint to confirm variables are set
3. **Check Google Console:** Ensure all redirect URIs are exactly correct
4. **Test step by step:** Use the debug endpoint after each configuration change

## 📞 **Quick Debug Checklist**
- [ ] Google Cloud project created
- [ ] Gmail API enabled
- [ ] OAuth consent screen configured
- [ ] OAuth 2.0 client created with correct redirect URIs
- [ ] Environment variables added to Render
- [ ] Render service redeployed
- [ ] Debug endpoint shows all variables as `true`