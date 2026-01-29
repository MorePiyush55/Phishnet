# PhishNet Render Deployment Guide

## Overview

This guide covers deploying PhishNet backend to Render with **both Mode 1 (automatic IMAP) and Mode 2 (on-demand Gmail API)** running on the same instance.

---

## Prerequisites

1. **Render Account**: Sign up at https://render.com
2. **MongoDB Atlas**: Free tier at https://www.mongodb.com/cloud/atlas
3. **Redis**: Use Render's Redis or Upstash
4. **Gmail App Passwords**: For IMAP and SMTP
5. **API Keys**: VirusTotal, Gemini, AbuseIPDB

---

## Step 1: Prepare External Services

### MongoDB Atlas

1. Create free cluster at https://cloud.mongodb.com
2. Create database user
3. Whitelist all IPs (0.0.0.0/0) for Render
4. Get connection string:
   ```
   mongodb+srv://username:password@cluster.mongodb.net/phishnet?retryWrites=true&w=majority
   ```

### Redis

**Option A: Render Redis**
1. Go to Render Dashboard → New → Redis
2. Choose free tier
3. Copy internal connection URL

**Option B: Upstash**
1. Sign up at https://upstash.com
2. Create Redis database
3. Copy connection URL

### Gmail App Passwords

1. Go to https://myaccount.google.com/apppasswords
2. Create app password for "IMAP" (for Mode 1)
3. Create app password for "SMTP" (for email replies)
4. Save both passwords securely

---

## Step 2: Deploy to Render

### Method 1: Using render.yaml (Recommended)

1. **Push render.yaml to your repo**:
   ```bash
   git add render.yaml
   git commit -m "Add Render deployment config"
   git push
   ```

2. **Create New Web Service**:
   - Go to Render Dashboard → New → Blueprint
   - Connect your GitHub repository
   - Select `backend/render.yaml`
   - Click "Apply"

3. **Set Secret Environment Variables**:
   
   Go to Dashboard → phishnet-backend → Environment
   
   Add the following secrets:
   
   ```
   MONGODB_URI=mongodb+srv://...
   REDIS_URL=redis://...
   
   # Mode 1 IMAP
   IMAP_USER=phishnet.ai@gmail.com
   IMAP_PASSWORD=<gmail-app-password>
   
   # Mode 2 Gmail API
   GMAIL_CLIENT_ID=<your-client-id>
   GMAIL_CLIENT_SECRET=<your-client-secret>
   
   # External APIs
   VIRUSTOTAL_API_KEY=<your-key>
   GOOGLE_API_KEY=<your-gemini-key>
   ABUSEIPDB_API_KEY=<your-key>
   
   # SMTP
   SMTP_USER=phishnet.ai@gmail.com
   SMTP_PASSWORD=<gmail-app-password>
   ```

4. **Deploy**:
   - Render will automatically build and deploy
   - Wait for deployment to complete (~5 minutes)

### Method 2: Manual Setup

1. **Create New Web Service**:
   - Dashboard → New → Web Service
   - Connect GitHub repository
   - Select `backend` directory
   - Name: `phishnet-backend`
   - Environment: `Python 3`
   - Build Command: `pip install -r requirements.txt`
   - Start Command: `uvicorn app.main:app --host 0.0.0.0 --port $PORT`

2. **Set Environment Variables** (same as Method 1)

3. **Deploy**

---

## Step 3: Verify Deployment

### Check Health

```bash
curl https://phishnet-backend.onrender.com/health
```

Expected:
```json
{
  "status": "healthy",
  "timestamp": "2024-01-29T...",
  "mode1_enabled": true
}
```

### Check Mode 1 Status

```bash
curl https://phishnet-backend.onrender.com/api/v1/mode1/status
```

Expected:
```json
{
  "running": true,
  "active_jobs": 0,
  "polling_tasks": ["default"]
}
```

### Check Mode 2 (On-Demand)

Mode 2 is automatically available at:
- `/api/v2/request-check` - Request email analysis
- `/api/v2/auth/google` - OAuth flow

---

## Step 4: Configure Frontend

Update your Vercel frontend environment variables:

```
NEXT_PUBLIC_API_URL=https://phishnet-backend.onrender.com
```

---

## Important Notes

### Mode 1 + Mode 2 Coordination

Both modes run on the same instance:
- **Mode 1**: Automatically polls IMAP inbox every 60 seconds
- **Mode 2**: Handles on-demand requests via API

**IMAP Ownership**: By default, Mode 1 owns the IMAP inbox. If you want both modes to access the same inbox, set:
```
# In mailbox config
ownership: "shared"
```

### Render Free Tier Limitations

- **Sleeps after 15 minutes of inactivity**
- **750 hours/month free**
- First request after sleep takes ~30 seconds

**Solution**: Upgrade to paid plan ($7/month) for always-on service.

### Monitoring

Render provides basic monitoring:
- Dashboard → Service → Metrics
- View CPU, Memory, Request count

For advanced monitoring (Prometheus/Grafana), use external services or upgrade plan.

---

## Troubleshooting

### Mode 1 Not Starting

Check logs:
```bash
# In Render Dashboard → Logs
# Look for:
# "Mode 1 Enterprise Orchestrator started automatically"
```

If not found:
1. Verify `MODE1_ENABLED=true`
2. Verify `MODE1_AUTO_START=true`
3. Check IMAP credentials are correct

### IMAP Connection Errors

```
Error: IMAP connection failed
```

**Fix**:
1. Verify Gmail app password (not regular password)
2. Enable "Less secure app access" (if using old Gmail)
3. Check IMAP is enabled in Gmail settings

### Circuit Breakers Open

```
Circuit breaker 'virustotal' is open
```

**Fix**:
1. Check API key is valid
2. Verify API quota not exceeded
3. Wait for circuit breaker to reset (60 seconds)

### Memory Issues

Render free tier has 512MB RAM. If exceeded:
1. Reduce `MODE1_BATCH_SIZE` to 25
2. Reduce `MODE1_MAX_CONCURRENT_TENANTS` to 5
3. Upgrade to paid plan

---

## Scaling

### Horizontal Scaling

Render supports multiple instances:
1. Dashboard → Service → Settings
2. Set "Instance Count" > 1
3. **Important**: Only one instance should run Mode 1 (set `MODE1_ENABLED=true` on one instance only)

### Vertical Scaling

Upgrade instance size:
- Starter: 512MB RAM, 0.5 CPU
- Standard: 2GB RAM, 1 CPU
- Pro: 4GB RAM, 2 CPU

---

## Cost Estimate

**Free Tier**:
- Web Service: Free (with sleep)
- Redis: Free (25MB)
- Total: $0/month

**Production**:
- Web Service (Starter): $7/month
- Redis (Starter): $10/month
- MongoDB Atlas: Free (512MB)
- Total: **$17/month**

---

## Next Steps

1. ✅ Deploy to Render
2. ✅ Verify both Mode 1 and Mode 2 work
3. ✅ Configure frontend to use Render URL
4. ✅ Test end-to-end flow
5. ✅ Monitor logs for 24 hours
6. ✅ Upgrade to paid plan (remove sleep)

---

## Support

- Render Docs: https://render.com/docs
- PhishNet Issues: GitHub Issues
- Mode 1 Docs: `docs/MODE1_INFRASTRUCTURE_SETUP.md`
