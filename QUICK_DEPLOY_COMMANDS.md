# 🎯 Quick Deployment Commands

## Copy-Paste Ready Commands for Deployment

---

## 🔑 Generate Secret Keys

```powershell
# Generate SECRET_KEY (copy output)
python -c "import secrets; print(secrets.token_urlsafe(32))"

# Generate JWT_SECRET_KEY (copy output)
python -c "import secrets; print(secrets.token_urlsafe(32))"
```

---

## 🧪 Test Local Backend (Before Deployment)

```powershell
cd C:\Users\piyus\AppData\Local\Programs\Python\Python313\project\Phishnet\backend
uvicorn app.main:app --reload
```

Visit: http://localhost:8000/docs

---

## 🧪 Test Local Frontend (Before Deployment)

```powershell
cd C:\Users\piyus\AppData\Local\Programs\Python\Python313\project\Phishnet\frontend
npm install
npm run dev
```

Visit: http://localhost:3000

---

## ☁️ Render Environment Variables (Copy-Paste)

```bash
PYTHON_VERSION=3.13
PORT=10000
ENVIRONMENT=production
DEBUG=false

# MongoDB (Replace with your connection string)
MONGODB_URL=mongodb+srv://username:password@cluster.mongodb.net/phishnet?retryWrites=true&w=majority

# Security (Replace with generated keys)
SECRET_KEY=paste_your_generated_secret_key_here
JWT_SECRET_KEY=paste_your_generated_jwt_secret_key_here

# IMAP Email (propam5553@gmail.com)
IMAP_ENABLED=true
IMAP_HOST=imap.gmail.com
IMAP_PORT=993
IMAP_USER=propam5553@gmail.com
IMAP_PASSWORD=your_gmail_app_password_here
IMAP_FOLDER=INBOX
IMAP_POLL_INTERVAL=60

# CORS (Update after Vercel deployment)
CORS_ORIGINS=https://your-vercel-url.vercel.app,http://localhost:3000
FRONTEND_URL=https://your-vercel-url.vercel.app

# App Info
APP_NAME=PhishNet
APP_VERSION=1.0.0
```

---

## 🌐 Vercel Environment Variables (Copy-Paste)

```bash
# Backend API URL (Update after Render deployment)
VITE_API_URL=https://phishnet-backend.onrender.com

# App Settings
VITE_APP_NAME=PhishNet
VITE_APP_VERSION=1.0.0
VITE_ENVIRONMENT=production
```

---

## 📊 MongoDB Connection String Template

```
mongodb+srv://<username>:<password>@<cluster-name>.mongodb.net/<database>?retryWrites=true&w=majority
```

**Example:**
```
mongodb+srv://phishnet-admin:MySecurePass123@phishnet-db.abc123.mongodb.net/phishnet?retryWrites=true&w=majority
```

**Replace:**
- `<username>` → Your database username (e.g., phishnet-admin)
- `<password>` → Your database password
- `<cluster-name>` → Your cluster name
- `<database>` → phishnet

---

## ✅ Test Deployed Backend

```bash
# Health check
curl https://phishnet-backend.onrender.com/health

# IMAP connection test
curl https://phishnet-backend.onrender.com/api/v1/imap-emails/test-connection

# List pending emails
curl https://phishnet-backend.onrender.com/api/v1/imap-emails/pending

# Get stats
curl https://phishnet-backend.onrender.com/api/v1/imap-emails/stats
```

---

## 📧 Gmail Setup Steps

1. **Enable 2FA:**
   - https://myaccount.google.com/security
   - Turn on 2-Step Verification

2. **Create App Password:**
   - https://myaccount.google.com/apppasswords
   - App: Mail
   - Device: PhishNet
   - Copy 16-character password

3. **Enable IMAP:**
   - Gmail Settings → Forwarding and POP/IMAP
   - Enable IMAP
   - Save Changes

---

## 🔄 Update Deployed Code

After making changes locally:

```powershell
# Commit and push
git add .
git commit -m "Your commit message"
git push origin main

# Render and Vercel will auto-deploy!
```

---

## 🌍 Your Live URLs

After deployment, save these:

```
GitHub: https://github.com/MorePiyush55/Phishnet
Backend: https://phishnet-backend.onrender.com
Frontend: https://your-project.vercel.app
API Docs: https://phishnet-backend.onrender.com/docs
MongoDB: https://cloud.mongodb.com
```

---

## ⚡ Quick Links

| Service | Sign Up | Dashboard |
|---------|---------|-----------|
| **Render** | https://render.com | https://dashboard.render.com |
| **Vercel** | https://vercel.com | https://vercel.com/dashboard |
| **MongoDB** | https://cloud.mongodb.com | https://cloud.mongodb.com |
| **Gmail** | - | https://mail.google.com |

---

## 🚨 Emergency Commands

### Backend Not Responding:
```powershell
# Check Render logs
# Go to: https://dashboard.render.com → Your Service → Logs

# Redeploy manually
# Dashboard → Manual Deploy → Deploy Latest Commit
```

### Frontend Not Loading:
```powershell
# Check Vercel logs
# Go to: https://vercel.com/dashboard → Your Project → Deployments

# Redeploy
# Click on latest deployment → Redeploy
```

### Database Connection Issues:
```powershell
# Test connection string
# In MongoDB Atlas → Database → Connect → Test Connection

# Check Network Access
# Ensure 0.0.0.0/0 is whitelisted
```

---

## 📞 Support

- **Render Docs:** https://render.com/docs
- **Vercel Docs:** https://vercel.com/docs
- **MongoDB Docs:** https://docs.atlas.mongodb.com
- **Your Docs:** See DEPLOYMENT_GUIDE.md

---

**Save this file for quick reference during deployment!** 📌
