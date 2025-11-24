# 🚀 PhishNet Deployment Guide
## Deploy Backend on Render + Frontend on Vercel

---

## 📋 Prerequisites

- [ ] GitHub account
- [ ] Render account (https://render.com - Free tier available)
- [ ] Vercel account (https://vercel.com - Free tier available)
- [ ] MongoDB Atlas account (https://cloud.mongodb.com - Free tier available)
- [ ] Gmail account with App Password (for IMAP - propam5553@gmail.com)

---

## 🎯 Deployment Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    Users / Browsers                      │
└─────────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────┐
│   Vercel (Frontend)                                      │
│   - React/TypeScript app                                │
│   - Static hosting                                       │
│   - Automatic deployments from GitHub                   │
│   URL: https://phishnet-frontend.vercel.app             │
└─────────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────┐
│   Render (Backend API)                                   │
│   - FastAPI Python server                               │
│   - Docker container or Python buildpack                │
│   - Automatic deployments from GitHub                   │
│   URL: https://phishnet-backend.onrender.com            │
└─────────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────┐
│   MongoDB Atlas (Database)                               │
│   - Free M0 cluster                                     │
│   - Managed cloud database                              │
└─────────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────┐
│   Gmail IMAP (Email Service)                            │
│   - propam5553@gmail.com                                │
│   - App Password authentication                         │
└─────────────────────────────────────────────────────────┘
```

---

## 📦 Part 1: Push to GitHub

### Step 1: Check Git Status

```powershell
cd C:\Users\piyus\AppData\Local\Programs\Python\Python313\project\Phishnet
git status
```

### Step 2: Stage All Changes

```powershell
# Add all new files and changes
git add .

# Check what will be committed
git status
```

### Step 3: Commit Changes

```powershell
git commit -m "Add IMAP email integration with real email support

- Implemented ThePhish-style IMAP forwarding workflow
- Added QuickIMAPService for email fetching and parsing
- Created 4 REST API endpoints for IMAP operations
- Integrated with EnhancedPhishingAnalyzer (5 modules)
- Added comprehensive documentation (2000+ lines)
- Configured for real email testing (propam5553@gmail.com)
- Ready for Render and Vercel deployment"
```

### Step 4: Push to GitHub

```powershell
# If this is your first push
git branch -M main
git remote add origin https://github.com/MorePiyush55/Phishnet.git
git push -u origin main

# If repository already exists
git push origin main
```

**⚠️ IMPORTANT:** Make sure `.env` files are in `.gitignore` (they already are!)

---

## 🔧 Part 2: Deploy Backend on Render

### Step 1: Create Render Account
1. Go to https://render.com
2. Sign up with GitHub account
3. Connect your GitHub account

### Step 2: Create New Web Service

1. Click **"New +"** → **"Web Service"**
2. Connect your GitHub repository: `MorePiyush55/Phishnet`
3. Configure:
   - **Name:** `phishnet-backend`
   - **Region:** Choose closest to you
   - **Branch:** `main`
   - **Root Directory:** `backend`
   - **Runtime:** `Python 3`
   - **Build Command:** `pip install --no-cache-dir -r requirements.txt`
   - **Start Command:** `uvicorn app.main:app --host 0.0.0.0 --port $PORT`
   - **Plan:** Free (for testing) or Starter ($7/month)

### Step 3: Configure Environment Variables

In Render dashboard, add these environment variables:

#### Required Variables:
```bash
# Python
PYTHON_VERSION=3.13

# MongoDB (from MongoDB Atlas)
MONGODB_URL=mongodb+srv://username:password@cluster.mongodb.net/phishnet?retryWrites=true&w=majority

# Security
SECRET_KEY=your-secret-key-min-32-chars
JWT_SECRET_KEY=your-jwt-secret-key-min-32-chars

# CORS (Update with your Vercel URL after deployment)
CORS_ORIGINS=https://your-vercel-url.vercel.app,http://localhost:3000
FRONTEND_URL=https://your-vercel-url.vercel.app

# IMAP Email Integration
IMAP_ENABLED=true
IMAP_HOST=imap.gmail.com
IMAP_PORT=993
IMAP_USER=propam5553@gmail.com
IMAP_PASSWORD=your-gmail-app-password-here
IMAP_FOLDER=INBOX
IMAP_POLL_INTERVAL=60

# App Settings
ENVIRONMENT=production
DEBUG=false
APP_NAME=PhishNet
APP_VERSION=1.0.0
```

#### Optional Variables:
```bash
# Redis (if using)
REDIS_URL=redis://your-redis-url

# Google OAuth (if needed)
GOOGLE_CLIENT_ID=your-google-client-id
GOOGLE_CLIENT_SECRET=your-google-client-secret
GOOGLE_REDIRECT_URI=https://phishnet-backend.onrender.com/auth/google/callback

# Email Notifications
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=propam5553@gmail.com
SMTP_PASSWORD=your-smtp-app-password
```

### Step 4: Deploy

1. Click **"Create Web Service"**
2. Wait for build to complete (5-10 minutes)
3. Check logs for any errors
4. Visit your backend URL: `https://phishnet-backend.onrender.com`
5. Test health endpoint: `https://phishnet-backend.onrender.com/health`
6. View API docs: `https://phishnet-backend.onrender.com/docs`

---

## 🌐 Part 3: Deploy Frontend on Vercel

### Step 1: Create Vercel Account
1. Go to https://vercel.com
2. Sign up with GitHub account
3. Connect your GitHub account

### Step 2: Import Project

1. Click **"Add New..."** → **"Project"**
2. Import `MorePiyush55/Phishnet`
3. Configure:
   - **Framework Preset:** Vite
   - **Root Directory:** `frontend`
   - **Build Command:** `npm run build`
   - **Output Directory:** `dist`

### Step 3: Configure Environment Variables

In Vercel dashboard, add these variables:

```bash
# Backend API URL (from Render)
VITE_API_URL=https://phishnet-backend.onrender.com

# App Settings
VITE_APP_NAME=PhishNet
VITE_APP_VERSION=1.0.0
VITE_ENVIRONMENT=production
```

### Step 4: Deploy

1. Click **"Deploy"**
2. Wait for build (2-5 minutes)
3. Get your Vercel URL: `https://your-project.vercel.app`
4. Test the application

### Step 5: Update Backend CORS

Go back to Render and update `CORS_ORIGINS` and `FRONTEND_URL` with your Vercel URL:

```bash
CORS_ORIGINS=https://your-project.vercel.app,http://localhost:3000
FRONTEND_URL=https://your-project.vercel.app
```

Render will automatically redeploy with new settings.

---

## 🗄️ Part 4: Setup MongoDB Atlas

### Step 1: Create MongoDB Atlas Account
1. Go to https://cloud.mongodb.com
2. Sign up for free account
3. Create organization and project

### Step 2: Create Free Cluster

1. Click **"Build a Database"**
2. Choose **FREE** tier (M0)
3. Select region closest to your Render deployment
4. Name cluster: `PhishNet-DB`
5. Click **"Create"**

### Step 3: Configure Database Access

1. Go to **Database Access** (left sidebar)
2. Click **"Add New Database User"**
3. Create user:
   - Username: `phishnet-admin`
   - Password: Generate secure password (save it!)
   - Database User Privileges: Read and write to any database
4. Click **"Add User"**

### Step 4: Configure Network Access

1. Go to **Network Access** (left sidebar)
2. Click **"Add IP Address"**
3. Add:
   - **0.0.0.0/0** (Allow from anywhere) - for Render
   - Or add specific Render IP ranges
4. Click **"Confirm"**

### Step 5: Get Connection String

1. Go to **Database** → **Connect**
2. Choose **"Connect your application"**
3. Copy connection string:
   ```
   mongodb+srv://phishnet-admin:<password>@phishnet-db.xxxxx.mongodb.net/?retryWrites=true&w=majority
   ```
4. Replace `<password>` with your database user password
5. Add database name: `mongodb+srv://...mongodb.net/phishnet?retryWrites=true...`
6. Update `MONGODB_URL` in Render environment variables

---

## ✅ Part 5: Verify Deployment

### Backend Verification:

```bash
# Health check
curl https://phishnet-backend.onrender.com/health

# IMAP test connection
curl https://phishnet-backend.onrender.com/api/v1/imap-emails/test-connection

# List pending emails
curl https://phishnet-backend.onrender.com/api/v1/imap-emails/pending

# View API docs
# Visit: https://phishnet-backend.onrender.com/docs
```

### Frontend Verification:

1. Visit your Vercel URL
2. Check if frontend loads
3. Test login (if authentication is set up)
4. Check if API calls work
5. Test IMAP email integration workflow

### Database Verification:

1. Go to MongoDB Atlas dashboard
2. Click **"Browse Collections"**
3. Check if `phishnet` database is created
4. Verify collections exist

---

## 🔒 Part 6: Security Checklist

### Before Going Live:

- [ ] All `.env` files are in `.gitignore`
- [ ] No sensitive data committed to GitHub
- [ ] Strong `SECRET_KEY` and `JWT_SECRET_KEY` generated
- [ ] MongoDB user has strong password
- [ ] CORS configured with specific domains (not `*`)
- [ ] Gmail App Password created (not regular password)
- [ ] 2FA enabled on propam5553@gmail.com
- [ ] HTTPS enabled on both frontend and backend
- [ ] Rate limiting configured (if needed)
- [ ] API endpoints require authentication

### Generate Strong Secrets:

```powershell
# In PowerShell
# Generate SECRET_KEY
python -c "import secrets; print(secrets.token_urlsafe(32))"

# Generate JWT_SECRET_KEY
python -c "import secrets; print(secrets.token_urlsafe(32))"
```

---

## 🔄 Part 7: Continuous Deployment

### Automatic Deployments:

Both Render and Vercel will automatically deploy when you push to GitHub!

```powershell
# Make changes to your code
git add .
git commit -m "Your commit message"
git push origin main

# Render will automatically redeploy backend
# Vercel will automatically redeploy frontend
```

### Manual Deployments:

**Render:**
1. Go to your service dashboard
2. Click **"Manual Deploy"** → **"Deploy latest commit"**

**Vercel:**
1. Go to your project dashboard
2. Click **"Redeploy"**

---

## 📊 Part 8: Monitoring

### Render Monitoring:

1. **Logs:** View real-time logs in Render dashboard
2. **Metrics:** CPU, memory usage available
3. **Health Checks:** Automatic at `/health` endpoint
4. **Alerts:** Set up email alerts for failures

### Vercel Monitoring:

1. **Analytics:** View page views, performance
2. **Logs:** Runtime and build logs
3. **Performance:** Web vitals tracking
4. **Errors:** Automatic error tracking

### MongoDB Monitoring:

1. **Metrics:** Database size, operations/sec
2. **Performance Advisor:** Query optimization tips
3. **Alerts:** Set up for high usage
4. **Backups:** Automatic on paid tiers

---

## 🚨 Troubleshooting

### Backend Issues:

**Build Fails:**
```bash
# Check requirements.txt compatibility
# Verify Python version (3.13)
# Check Render build logs
```

**App Crashes:**
```bash
# Check environment variables
# Verify MongoDB connection string
# Check application logs in Render
# Test IMAP credentials
```

**IMAP Connection Fails:**
```bash
# Verify Gmail App Password
# Check IMAP enabled in Gmail
# Verify propam5553@gmail.com credentials
# Check firewall/network settings
```

### Frontend Issues:

**Build Fails:**
```bash
# Check package.json dependencies
# Verify Node.js version
# Check Vercel build logs
```

**API Calls Fail:**
```bash
# Verify VITE_API_URL is correct
# Check CORS settings in backend
# Verify backend is running
# Check browser console for errors
```

### Database Issues:

**Connection Fails:**
```bash
# Verify MongoDB connection string
# Check network access (0.0.0.0/0)
# Verify database user credentials
# Check MongoDB Atlas status
```

---

## 💰 Cost Breakdown

### Free Tier (Good for testing):
- **Render Free:** 750 hours/month, sleeps after 15 min inactivity
- **Vercel Free:** Unlimited deployments, 100GB bandwidth
- **MongoDB Atlas Free:** 512MB storage, shared cluster

### Production (Recommended):
- **Render Starter:** $7/month (no sleep, better performance)
- **Vercel Pro:** $20/month (more bandwidth, better support)
- **MongoDB Atlas M10:** $10/month (dedicated cluster, backups)

**Total Production Cost:** ~$37/month

---

## 🎯 Post-Deployment Checklist

- [ ] Backend deployed on Render
- [ ] Frontend deployed on Vercel
- [ ] MongoDB Atlas configured
- [ ] Environment variables set
- [ ] CORS configured correctly
- [ ] IMAP connection tested
- [ ] Health endpoints responding
- [ ] API documentation accessible
- [ ] Frontend loading properly
- [ ] Authentication working
- [ ] Email forwarding tested
- [ ] Analysis workflow verified
- [ ] Monitoring setup
- [ ] Backups configured
- [ ] Custom domain added (optional)

---

## 📞 Support Resources

### Render:
- Docs: https://render.com/docs
- Status: https://status.render.com
- Support: support@render.com

### Vercel:
- Docs: https://vercel.com/docs
- Status: https://vercel-status.com
- Support: support@vercel.com

### MongoDB Atlas:
- Docs: https://docs.atlas.mongodb.com
- Status: https://status.mongodb.com
- Support: MongoDB University (free training)

---

## 🎉 You're Live!

Once deployed, your PhishNet application will be accessible at:

- **Frontend:** https://your-project.vercel.app
- **Backend API:** https://phishnet-backend.onrender.com
- **API Docs:** https://phishnet-backend.onrender.com/docs

**Share with users:**
- Forward suspicious emails as attachment to: propam5553@gmail.com
- Analysts access dashboard at your Vercel URL
- Real-time phishing detection with 5-module analysis!

---

**Need Help?** Check the documentation in `docs/` folder or review deployment logs.

**Happy Deploying! 🚀🔒**
