# PhishNet Deployment Guide

## Overview

PhishNet uses a modern cloud deployment architecture:
- **Backend**: Render (FastAPI Python)
- **Frontend**: Vercel (React/TypeScript)
- **Database**: MongoDB Atlas
- **Email**: Gmail IMAP + Brevo/Resend API

---

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    Users / Browsers                      │
└─────────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────┐
│   Vercel (Frontend)                                      │
│   URL: https://phishnet-tau.vercel.app                  │
└─────────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────┐
│   Render (Backend API)                                   │
│   URL: https://phishnet-backend-iuoc.onrender.com       │
└─────────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────┐
│   MongoDB Atlas        │   Gmail IMAP    │   Brevo API  │
│   (Database)           │   (Inbox)       │   (Replies)  │
└─────────────────────────────────────────────────────────┘
```

---

## Prerequisites

- GitHub account
- Render account (https://render.com)
- Vercel account (https://vercel.com)
- MongoDB Atlas account (https://cloud.mongodb.com)
- Gmail account with App Password

---

## Backend Deployment (Render)

### Step 1: Connect GitHub

1. Log in to Render Dashboard
2. Click **New** → **Web Service**
3. Connect your GitHub repository
4. Select the `Phishnet` repository

### Step 2: Configure Build

| Setting | Value |
|---------|-------|
| Name | `phishnet-backend` |
| Root Directory | `backend` |
| Runtime | `Python 3` |
| Build Command | `pip install -r requirements.txt` |
| Start Command | `uvicorn app.main:app --host 0.0.0.0 --port $PORT` |

### Step 3: Environment Variables

Add these in Render → Environment:

```env
# Required
MONGODB_URI=mongodb+srv://user:pass@cluster.mongodb.net/?retryWrites=true
SECRET_KEY=your-secret-key-min-32-chars
ENVIRONMENT=production

# IMAP (Email Forwarding)
IMAP_ENABLED=True
IMAP_HOST=imap.gmail.com
IMAP_USER=phishnet.ai@gmail.com
IMAP_PASSWORD=your-16-char-app-password

# Email Reply Service
BREVO_API_KEY=xkeysib-your-brevo-key

# AI Analysis
GEMINI_API_KEY=AIzaSy-your-gemini-key

# OAuth (Optional)
GMAIL_CLIENT_ID=your-client-id.apps.googleusercontent.com
GMAIL_CLIENT_SECRET=GOCSPX-your-secret
GMAIL_REDIRECT_URI=https://your-backend.onrender.com/api/v1/auth/gmail/callback

# Threat Intelligence (Optional)
VIRUSTOTAL_API_KEY=your-vt-key
ABUSEIPDB_API_KEY=your-abuseipdb-key

# CORS
CORS_ORIGINS=["https://phishnet-tau.vercel.app","http://localhost:3000"]
BASE_URL=https://phishnet-backend-iuoc.onrender.com
FRONTEND_URL=https://phishnet-tau.vercel.app
```

### Step 4: Deploy

Click **Create Web Service**. Render will automatically deploy on every git push.

---

## Frontend Deployment (Vercel)

### Step 1: Connect GitHub

1. Log in to Vercel
2. Click **Add New** → **Project**
3. Import from GitHub → Select `Phishnet`

### Step 2: Configure Build

| Setting | Value |
|---------|-------|
| Root Directory | `frontend` |
| Framework Preset | `Vite` |
| Build Command | `npm run build` |
| Output Directory | `dist` |

### Step 3: Environment Variables

```env
VITE_API_URL=https://phishnet-backend-iuoc.onrender.com
VITE_GOOGLE_CLIENT_ID=your-client-id.apps.googleusercontent.com
```

### Step 4: Deploy

Click **Deploy**. Vercel auto-deploys on every git push.

---

## MongoDB Atlas Setup

### Step 1: Create Cluster

1. Go to https://cloud.mongodb.com
2. Create a new project → **Build a Database**
3. Select **M0 Free Tier**
4. Choose cloud provider and region

### Step 2: Configure Access

1. **Database Access**: Create user with password
2. **Network Access**: Add `0.0.0.0/0` (allow all IPs for Render)

### Step 3: Get Connection String

1. Click **Connect** → **Connect your application**
2. Copy the connection string
3. Replace `<password>` with your actual password
4. Add to Render as `MONGODB_URI`

---

## Gmail App Password

1. Enable 2FA: https://myaccount.google.com/security
2. Generate App Password: https://myaccount.google.com/apppasswords
3. Select: Mail → Other (PhishNet)
4. Copy 16-character password (remove spaces)
5. Add to Render as `IMAP_PASSWORD`

---

## Email Service Setup

### Option A: Brevo (Recommended)

1. Sign up at https://brevo.com
2. Go to SMTP & API → API Keys
3. Create new key
4. Add to Render: `BREVO_API_KEY=xkeysib-...`

### Option B: Resend

1. Sign up at https://resend.com
2. Create API key
3. Verify a domain (required for external recipients)
4. Add to Render: `RESEND_API_KEY=re_...`

---

## Verification Checklist

After deployment, verify:

- [ ] Backend health: `https://your-backend.onrender.com/health`
- [ ] API docs: `https://your-backend.onrender.com/docs`
- [ ] Frontend loads: `https://your-frontend.vercel.app`
- [ ] IMAP connection: Check Render logs for "Found X recent emails"
- [ ] Email replies: Forward test email, check for reply

---

## Troubleshooting

### Backend won't start
- Check Render logs for errors
- Verify all required environment variables are set
- Ensure `requirements.txt` has all dependencies

### Database connection fails
- Check `MONGODB_URI` format
- Verify Network Access allows `0.0.0.0/0`
- Check username/password are correct

### CORS errors
- Add frontend URL to `CORS_ORIGINS`
- Ensure no trailing slashes in URLs

### IMAP "0 emails found"
- Regenerate Gmail App Password
- Verify IMAP enabled in Gmail settings
- Check `IMAP_HOST=imap.gmail.com`

### Emails not sending
- Check `BREVO_API_KEY` or `RESEND_API_KEY`
- Verify API key is active
- Check Render logs for send errors

---

## Custom Domain (Optional)

### Render (Backend)
1. Go to Settings → Custom Domains
2. Add domain: `api.yourdomain.com`
3. Add CNAME record pointing to Render URL

### Vercel (Frontend)
1. Go to Settings → Domains
2. Add domain: `yourdomain.com`
3. Follow DNS configuration instructions

---

## Scaling (Production)

### Render
- Upgrade to paid plan for:
  - No spin-down after inactivity
  - More CPU/RAM
  - Zero-downtime deploys

### MongoDB Atlas
- Upgrade to M10+ for:
  - More storage
  - Better performance
  - Automatic backups

### Caching (Optional)
- Add Redis for rate limiting
- Configure `REDIS_URL` in environment
