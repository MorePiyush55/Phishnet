# 🚀 **Quick Fix for Vercel Deployment**

## ❌ **Common Errors & Solutions**

### **Error 1**: `cd: frontend: No such directory`
### **Error 2**: `Deployment has been canceled as a result of running the command defined in the "Ignored Build Step" setting`
### **Error 3**: `404: NOT_FOUND - DEPLOYMENT_NOT_FOUND`

## ✅ **Root Cause & Solutions**

### **Issue**: Monorepo Configuration Problems
The errors occur because:
1. Vercel is trying to build from the root directory 
2. The `ignoreCommand` is canceling deployments
3. Root directory is not properly configured

## 🔧 **Step-by-Step Fix**

### **Step 1: Configure Root Directory in Vercel Dashboard**

1. **Go to your Vercel project**: https://vercel.com/dashboard
2. **Find your project** (`phishnet-frontend` or similar)
3. **Go to Settings → General**
4. **Configure these settings**:
   - **Root Directory**: `frontend` ⚠️ **CRITICAL**
   - **Framework Preset**: `Vite`
   - **Build Command**: `npm run build`
   - **Output Directory**: `dist`
   - **Install Command**: `npm install`
5. **Save settings**

### **Step 2: Force Redeploy**

1. **Go to Deployments tab**
2. **Click "Redeploy" on the latest deployment**
3. **OR trigger a new deployment by pushing a commit**

### **Step 3: Alternative - Delete & Recreate Project**

If the above doesn't work:

1. **Delete the current Vercel project**
2. **Create new project**:
   - Import: `https://github.com/MorePiyush55/Phishnet`
   - **Root Directory**: `frontend` ⚠️ **Set this during import**
   - **Framework**: `Vite`

## 🔧 **Environment Variables for Vercel**

Add these in Vercel Dashboard → Settings → Environment Variables:

```bash
VITE_API_URL=https://your-render-backend.onrender.com
VITE_WS_URL=wss://your-render-backend.onrender.com
VITE_APP_NAME=PhishNet
```

## 🎯 **Expected Result**

After fixing the configuration:
- ✅ Build should complete successfully
- ✅ Frontend will be accessible at `https://your-app.vercel.app`
- ✅ API calls will be proxied to your Render.com backend

## 🔗 **Update Backend CORS**

Once you get your Vercel URL, update your Render.com backend environment:

```bash
CORS_ORIGINS=https://your-vercel-app.vercel.app,http://localhost:3000
```

---

**🎉 This should resolve your Vercel deployment issue!**
