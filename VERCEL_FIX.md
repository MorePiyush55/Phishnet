# 🚀 **Quick Fix for Vercel Deployment**

## ❌ **Error**: `cd: frontend: No such directory`

The error occurs because Vercel is trying to build from the root directory but needs to build from the `frontend` subdirectory.

## ✅ **Solution**: Configure Root Directory in Vercel

### **Method 1: Via Vercel Dashboard (Recommended)**

1. Go to your Vercel project settings
2. Navigate to **Settings** → **General**
3. Set **Root Directory** to: `frontend`
4. Set **Framework Preset** to: `Vite`
5. Set **Build Command** to: `npm run build`
6. Set **Output Directory** to: `dist`
7. Set **Install Command** to: `npm install`
8. **Redeploy** the project

### **Method 2: Deploy Frontend Directory Directly**

```bash
# Clone your repo
git clone https://github.com/MorePiyush55/Phishnet.git
cd Phishnet/frontend

# Install Vercel CLI
npm install -g vercel

# Deploy from frontend directory
vercel --prod
```

### **Method 3: Update Deployment URL**

Instead of deploying the entire monorepo, deploy just the frontend:

1. Go to Vercel Dashboard
2. Click **"New Project"**
3. Import: `https://github.com/MorePiyush55/Phishnet`
4. **Configure these settings**:
   - **Root Directory**: `frontend`
   - **Framework**: Vite
   - **Build Command**: `npm run build`
   - **Output Directory**: `dist`

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
