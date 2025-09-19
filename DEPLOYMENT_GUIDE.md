# PhishNet Deployment Guide 🚀

## Overview
This guide will help you deploy PhishNet with:
- **Backend**: Render.com (with MongoDB Atlas)
- **Frontend**: Vercel.com 

## Prerequisites
- GitHub repository with latest changes
- Render.com account
- Vercel.com account  
- MongoDB Atlas cluster (already configured)

---

## 🔧 Backend Deployment (Render)

### 1. Prepare Repository
Ensure your backend code is committed and pushed:
```bash
cd backend
git add .
git commit -m "Prepare backend for Render deployment"
git push origin main
```

### 2. Deploy to Render

1. **Go to [Render.com](https://render.com)** and sign in
2. **Click "New +"** → **"Web Service"**
3. **Connect Repository**: Select your GitHub repository
4. **Configure Service**:
   - **Name**: `phishnet-backend`
   - **Region**: Choose closest to your users
   - **Branch**: `main`
   - **Root Directory**: `backend`
   - **Runtime**: `Python 3`
   - **Build Command**: `pip install --no-cache-dir -r requirements.txt`
   - **Start Command**: `python main.py`

5. **Environment Variables** (Add these in Render dashboard):
   ```
   MONGODB_URI=mongodb+srv://Propam:Propam%405553@phisnet-db.4qvmhkw.mongodb.net/?retryWrites=true&w=majority&appName=PhisNet-DB
   SECRET_KEY=your-super-secret-key-here
   ENVIRONMENT=production
   DEBUG=false
   CORS_ORIGINS=https://phishnet-frontend.vercel.app,https://localhost:3000
   APP_NAME=PhishNet
   APP_VERSION=1.0.0
   ```

6. **Deploy**: Click "Create Web Service"

### 3. Verify Backend Deployment
Once deployed, test your backend:
```bash
# Replace with your Render URL
curl https://phishnet-backend.onrender.com/health
curl https://phishnet-backend.onrender.com/api/auth/test
```

---

## 🌐 Frontend Deployment (Vercel)

### 1. Prepare Frontend
Update frontend configuration:
```bash
cd frontend
# Verify vercel.json is configured correctly
# Verify .env.production has correct backend URL
```

### 2. Deploy to Vercel

**Option A: Vercel CLI (Recommended)**
```bash
# Install Vercel CLI
npm i -g vercel

# Deploy from frontend directory
cd frontend
vercel

# Follow prompts:
# - Link to existing project or create new
# - Set project name: phishnet-frontend
# - Set framework: Vite
# - Set build command: npm run build
# - Set output directory: dist
```

**Option B: Vercel Dashboard**
1. **Go to [Vercel.com](https://vercel.com)** and sign in
2. **Click "New Project"**
3. **Import Repository**: Select your GitHub repository
4. **Configure Project**:
   - **Project Name**: `phishnet-frontend`
   - **Framework Preset**: `Vite`
   - **Root Directory**: `frontend`
   - **Build Command**: `npm run build`
   - **Output Directory**: `dist`

5. **Environment Variables** (Add in Vercel dashboard):
   ```
   VITE_API_BASE_URL=https://phishnet-backend.onrender.com
   VITE_API_URL=https://phishnet-backend.onrender.com
   VITE_ENVIRONMENT=production
   VITE_APP_TITLE=PhishNet - Email Security Monitoring
   ```

6. **Deploy**: Click "Deploy"

### 3. Update Backend CORS
After frontend deployment, update backend CORS settings with your Vercel URL:
```bash
# In Render dashboard, update CORS_ORIGINS environment variable:
CORS_ORIGINS=https://your-vercel-url.vercel.app,https://localhost:3000
```

---

## 🧪 Testing Deployed Applications

### Backend Tests
```bash
# Health check
curl https://phishnet-backend.onrender.com/health

# Auth test  
curl https://phishnet-backend.onrender.com/api/auth/test

# Register user
curl -X POST https://phishnet-backend.onrender.com/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","username":"testuser","password":"password123"}'

# Login
curl -X POST https://phishnet-backend.onrender.com/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","password":"password123"}'
```

### Frontend Tests  
1. **Visit your Vercel URL**: `https://your-app.vercel.app`
2. **Test registration/login**
3. **Test email analysis features**
4. **Check browser console for errors**

---

## 🔧 Troubleshooting

### Common Backend Issues
- **MongoDB Connection**: Verify MongoDB Atlas IP whitelist (allow 0.0.0.0/0 for Render)
- **Environment Variables**: Double-check all required env vars in Render dashboard
- **Build Failures**: Check Render build logs for Python dependency issues

### Common Frontend Issues  
- **API Calls Failing**: Verify VITE_API_BASE_URL points to correct Render URL
- **CORS Errors**: Update backend CORS_ORIGINS with frontend Vercel URL
- **Build Failures**: Check Vercel build logs for Node.js/npm issues

### Debug Commands
```bash
# Check Render logs
# Go to Render dashboard → Service → Logs

# Check Vercel logs  
# Go to Vercel dashboard → Project → Functions

# Test API connectivity
curl -v https://phishnet-backend.onrender.com/health
```

---

## 📊 Production Checklist

### Backend (Render)
- ✅ MongoDB Atlas connection working
- ✅ Environment variables configured
- ✅ Health checks passing (/health endpoint)
- ✅ Authentication endpoints working
- ✅ Email analysis endpoints working
- ✅ CORS configured for frontend domain

### Frontend (Vercel)
- ✅ Build succeeds without errors
- ✅ Environment variables configured
- ✅ API endpoints pointing to Render backend
- ✅ Authentication flow working
- ✅ Email analysis features working
- ✅ Responsive design working

### Integration
- ✅ Frontend can communicate with backend
- ✅ User registration/login works end-to-end
- ✅ Email analysis works end-to-end
- ✅ No CORS errors
- ✅ HTTPS working on both platforms

---

## 🎯 URLs After Deployment

- **Backend**: `https://phishnet-backend.onrender.com`
- **Frontend**: `https://phishnet-frontend.vercel.app`
- **API Docs**: `https://phishnet-backend.onrender.com/docs`
- **Health Check**: `https://phishnet-backend.onrender.com/health`

---

## 🚀 Next Steps After Deployment

1. **Custom Domains** (Optional):
   - Configure custom domain for frontend in Vercel
   - Configure custom domain for backend in Render

2. **Monitoring**:
   - Set up Render health check alerts
   - Configure Vercel analytics

3. **Security**:
   - Review and rotate secret keys
   - Set up proper CORS policies
   - Configure rate limiting

4. **Performance**:
   - Enable Vercel analytics
   - Monitor Render performance metrics
   - Optimize API response times

Happy deploying! 🎉