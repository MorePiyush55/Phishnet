# 🔧 Quick Fix for OAuth Token Exchange

## 🚨 **Immediate Action Required**

I found the issue! You need to add one more environment variable to Render:

### **Add This Environment Variable to Render:**

1. **Go to Render Dashboard**: https://dashboard.render.com/
2. **Select your PhishNet backend service**
3. **Go to Environment tab**
4. **Add this variable:**

```bash
BASE_URL=https://phishnet-backend-iuoc.onrender.com
```

## 🔍 **Why This Fixes the Issue:**

The OAuth flow has a redirect URI mismatch:
- **OAuth initiation**: Uses `/api/test/oauth/callback` (from your test endpoint)
- **Token exchange**: Tries to construct URL but `BASE_URL` is "Not set"
- **Google validation**: Fails because redirect URIs don't match exactly

## ✅ **After Adding BASE_URL:**

1. **Render will auto-redeploy** (2-3 minutes)
2. **Check config again**: `https://phishnet-backend-iuoc.onrender.com/api/debug/oauth-config`
3. **Should show**: `"base_url": "https://phishnet-backend-iuoc.onrender.com"`
4. **Test OAuth**: Should work without `token_exchange_failed`

## 🎯 **Alternative Quick Test:**

While waiting for Render to redeploy, you can also test the main OAuth endpoint:
```
https://phishnet-backend-iuoc.onrender.com/api/v1/auth/gmail/callback
```

This uses the `GMAIL_REDIRECT_URI` which is properly configured.

## 🔮 **Expected Result:**

After adding `BASE_URL`, the OAuth flow will complete successfully:
- ✅ No more redirect URI mismatch
- ✅ Token exchange works properly  
- ✅ User gets logged into PhishNet dashboard
- ✅ `oauth_success=true` instead of `oauth_error=token_exchange_failed`

This should be the final piece to make your OAuth flow work perfectly! 🎉