# 🚀 Vercel Deployment Fix - Routes vs Modern Configuration

## ❌ **The Error Explained**

The error occurs because Vercel's configuration has evolved:

- **Legacy**: `routes` property (Vercel v1 style)
- **Modern**: `rewrites`, `redirects`, `headers`, `cleanUrls`, `trailingSlash` (Vercel v2 style)

**You cannot use both in the same `vercel.json` file.**

## ✅ **Fixed Configuration**

Your `vercel.json` has been updated to use the modern Vercel v2 configuration:

```json
{
  "version": 2,
  "name": "phishnet-frontend",
  "framework": "vite",
  "buildCommand": "npm run build",
  "outputDirectory": "dist",
  "installCommand": "npm install",
  "cleanUrls": true,
  "trailingSlash": false,
  "rewrites": [
    {
      "source": "/((?!_next|favicon.ico|sw.js|manifest.json|assets).*)",
      "destination": "/index.html"
    }
  ],
  "headers": [
    {
      "source": "/(.*)",
      "headers": [
        {
          "key": "X-Content-Type-Options",
          "value": "nosniff"
        },
        {
          "key": "X-Frame-Options", 
          "value": "DENY"
        },
        {
          "key": "X-XSS-Protection",
          "value": "1; mode=block"
        },
        {
          "key": "Referrer-Policy",
          "value": "strict-origin-when-cross-origin"
        },
        {
          "key": "Permissions-Policy",
          "value": "camera=(), microphone=(), geolocation=()"
        }
      ]
    },
    {
      "source": "/oauth/(.*)",
      "headers": [
        {
          "key": "Cache-Control",
          "value": "no-cache, no-store, must-revalidate"
        }
      ]
    },
    {
      "source": "/(.*\\.(js|css|png|jpg|jpeg|gif|svg|ico|woff|woff2|ttf|eot))",
      "headers": [
        {
          "key": "Cache-Control",
          "value": "public, max-age=31536000, immutable"
        }
      ]
    }
  ]
}
```

## 🔧 **What Changed**

### ❌ **Removed (Legacy)**
- `routes` array (incompatible with modern config)
- `redirects` (simplified for SPA)
- `functions` (not needed for frontend-only)

### ✅ **Kept (Modern)**
- `rewrites` for SPA routing
- `headers` for security
- `cleanUrls` and `trailingSlash` for clean URLs

## 🎯 **React SPA Routing**

The key rewrite rule handles React Router:
```json
{
  "source": "/((?!_next|favicon.ico|sw.js|manifest.json|assets).*)",
  "destination": "/index.html"
}
```

This ensures all routes (except static files) go to `index.html` for client-side routing.

## 🚀 **Deployment Steps**

1. **Commit the fixed vercel.json:**
   ```bash
   git add frontend/vercel.json
   git commit -m "🔧 Fix Vercel configuration - remove routes conflict"
   git push origin main
   ```

2. **Deploy to Vercel:**
   - Connect your GitHub repository
   - Vercel will auto-detect Vite framework
   - Set these environment variables:

   ```env
   VITE_API_BASE_URL=https://your-backend.onrender.com
   VITE_OAUTH_CLIENT_ID=your_google_client_id
   VITE_ENVIRONMENT=production
   ```

3. **Verify deployment:**
   - Check build logs for success
   - Test OAuth flow end-to-end
   - Verify all routes work correctly

## 🛠️ **Alternative Minimal Configuration**

If you still have issues, use this ultra-minimal config:

```json
{
  "rewrites": [
    {
      "source": "/(.*)",
      "destination": "/index.html"
    }
  ]
}
```

## 🔍 **Troubleshooting**

### **Common Issues:**

1. **Build Command**: Make sure `npm run build` works locally
2. **Output Directory**: Verify `dist` folder is created
3. **Environment Variables**: Double-check all VITE_ prefixed vars
4. **OAuth URLs**: Update Google Console with Vercel domain

### **Build Commands:**
```bash
# Local test
cd frontend
npm install
npm run build
npm run preview

# Check if dist/ folder is created correctly
```

## ✅ **Success Indicators**

Your deployment is successful when:
- ✅ Build completes without errors
- ✅ All routes redirect to index.html
- ✅ Static assets are cached properly
- ✅ Security headers are applied
- ✅ OAuth flow works end-to-end

## 🎉 **Ready to Deploy!**

Your `vercel.json` is now fixed and ready for production deployment on Vercel!

The configuration:
- ✅ **Modern Vercel v2 format**
- ✅ **Optimized for React SPA**
- ✅ **Security headers included**
- ✅ **Proper caching strategy**
- ✅ **OAuth-friendly routing**