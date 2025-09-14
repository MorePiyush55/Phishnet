# PhishNet OAuth Deployment Guide

## 🔧 **Backend Configuration (Render.com)**

Add these environment variables to your Render.com backend deployment:

```bash
# Google OAuth Credentials (replace with your actual values)
GOOGLE_CLIENT_ID=YOUR_GOOGLE_CLIENT_ID_FROM_CONSOLE
GOOGLE_CLIENT_SECRET=YOUR_GOOGLE_CLIENT_SECRET_FROM_CONSOLE
GOOGLE_PROJECT_ID=your-project-name

# OAuth URLs (replace with your actual Vercel domain)
GOOGLE_REDIRECT_URI=https://your-vercel-domain.vercel.app/auth/callback
FRONTEND_URL=https://your-vercel-domain.vercel.app
BACKEND_URL=https://your-backend-domain.onrender.com

# JWT Configuration
JWT_SECRET_KEY=generate-a-secure-random-secret-key
JWT_ALGORITHM=HS256
JWT_ACCESS_TOKEN_EXPIRE_MINUTES=60
JWT_REFRESH_TOKEN_EXPIRE_DAYS=7
```

## 🌐 **Frontend Configuration (Vercel)**

Update your Vercel environment variables:

```bash
VITE_GOOGLE_CLIENT_ID=YOUR_GOOGLE_CLIENT_ID_FROM_CONSOLE
VITE_API_URL=https://your-backend-domain.onrender.com
```

## 📋 **Google Cloud Console Setup**

1. Go to [Google Cloud Console](https://console.cloud.google.com)
2. Create or select your project
3. Navigate to APIs & Services > Credentials
4. Create OAuth 2.0 Client ID
5. Configure authorized domains:
   - **Authorized JavaScript origins**: `https://your-vercel-domain.vercel.app`
   - **Authorized redirect URIs**: `https://your-vercel-domain.vercel.app/auth/callback`

## ✅ **OAuth Flow Status**

- ✅ Google OAuth configuration templates ready
- ✅ Professional landing page designed
- ✅ Security best practices implemented
- ✅ Error handling and user feedback
- ✅ Backend OAuth endpoints ready
- ⚠️ **IMPORTANT**: Replace all placeholder values with actual credentials

## 🚀 **Deploy Instructions**

1. Get your Google OAuth credentials from Google Cloud Console
2. Add environment variables to Render.com backend
3. Deploy backend to Render.com
4. Add environment variables to Vercel frontend
5. Deploy frontend to Vercel
6. Update Google Cloud Console with your actual domains
7. Test the OAuth flow

The 400 error will be resolved once you configure the actual redirect URIs!