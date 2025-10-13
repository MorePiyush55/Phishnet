# IMAP Email Integration - Quick Start Guide

## 🚀 What's New

PhishNet now supports **ThePhish-style email forwarding** - a simple way for users to report suspicious emails without complex OAuth setup!

### How It Works
1. User receives suspicious email
2. User forwards it **as attachment** to phishnet@yourcompany.com
3. Analyst selects email from pending list
4. System analyzes with 5-module Enhanced Analyzer
5. Results stored in MongoDB, analyst receives report

---

## ⚡ 15-Minute Setup

### Step 1: Get Gmail App Password (5 minutes)

**⚠️ IMPORTANT: Using REAL email account propam5553@gmail.com**

1. Log in to **propam5553@gmail.com**
2. Go to https://myaccount.google.com/security
3. Enable 2-Factor Authentication if not already enabled
4. Go to https://myaccount.google.com/apppasswords
5. Select app: "Mail", device: "Other (PhishNet)"
6. Click "Generate"
7. **Copy the 16-character password** (example: `abcd efgh ijkl mnop`)

### Step 2: Configure IMAP (2 minutes)

Add to your `.env` file:

```bash
# IMAP Email Forwarding (ThePhish-style)
# ⚠️ Using REAL email account for testing
IMAP_ENABLED=true
IMAP_HOST=imap.gmail.com
IMAP_PORT=993
IMAP_USER=propam5553@gmail.com
IMAP_PASSWORD=your_16_char_app_password
IMAP_FOLDER=INBOX
IMAP_POLL_INTERVAL=60
```

**Replace:**
- `your_16_char_app_password` → App password from Step 1

**⚠️ NOTE:** This is your actual test email account. Use REAL phishing emails, not fake/test data!

### Step 3: Test Connection (3 minutes)

```powershell
# Navigate to backend
cd backend

# Run test script
python test_imap_integration.py
```

Expected output:
```
✅ IMAP connection successful!
```

If connection fails:
- ❌ Check App Password (remove spaces)
- ❌ Enable IMAP in Gmail: Settings → Forwarding and POP/IMAP → Enable IMAP
- ❌ Check firewall allows port 993

### Step 4: Test Forwarding (5 minutes)

**⚠️ Use REAL phishing emails, not test/fake emails!**

1. Find a **REAL phishing email** (check spam folder in propam5553@gmail.com)
2. Open the suspicious email
3. Click **More (⋮)** → **Forward as attachment**
4. Send to: `propam5553@gmail.com`
5. Run test script again:
   ```powershell
   python test_imap_integration.py
   ```

**💡 Where to find real phishing emails:**
- Gmail spam folder
- Security alerts
- Phishing simulation campaigns
- User-reported suspicious emails

Expected output:
```
✅ Found 1 pending email(s):
1. UID: 12345
   From: sender@example.com
   Subject: Test Email
   Date: 2024-01-15 10:30:00
```

---

## 🔧 API Endpoints

### 1. Test Connection
```bash
GET /api/v1/imap-emails/test-connection
```

**Response:**
```json
{
  "success": true,
  "status": "connected",
  "folder": "INBOX",
  "message": "Successfully connected to IMAP server"
}
```

### 2. List Pending Emails
```bash
GET /api/v1/imap-emails/pending?skip=0&limit=20
```

**Response:**
```json
{
  "total": 5,
  "emails": [
    {
      "uid": "12345",
      "from": "user@company.com",
      "subject": "FW: Suspicious Email",
      "date": "2024-01-15T10:30:00",
      "has_attachment": true,
      "preview": "This email looks suspicious..."
    }
  ]
}
```

### 3. Analyze Email
```bash
POST /api/v1/imap-emails/analyze/12345
```

**Response:**
```json
{
  "analysis_id": "abc123",
  "verdict": "PHISHING",
  "confidence": 0.85,
  "total_score": 25,
  "sections": {
    "sender": {"score": 30, "weight": 15},
    "content": {"score": 20, "weight": 20},
    "links": {"score": 15, "weight": 20},
    "authentication": {"score": 40, "weight": 30},
    "attachments": {"score": 50, "weight": 15}
  },
  "risk_factors": [
    "Display name mismatch with email domain",
    "Multiple urgency keywords detected",
    "SPF check failed"
  ]
}
```

### 4. Get Statistics
```bash
GET /api/v1/imap-emails/stats
```

**Response:**
```json
{
  "total_analyzed": 150,
  "phishing_detected": 45,
  "legitimate": 80,
  "suspicious": 25,
  "detection_rate": 0.30
}
```

---

## 👥 User Guide

### For End Users: How to Report Suspicious Email

**⚠️ Forward REAL suspicious emails to: propam5553@gmail.com**

**Method 1: Gmail Web**
1. Open the suspicious email
2. Click **More (⋮)** button (top right)
3. Select **"Forward as attachment"**
4. To: `propam5553@gmail.com`
5. Click **Send**

**Method 2: Outlook Desktop**
1. Select the suspicious email
2. Go to **Home** → **More** → **Forward as Attachment**
3. To: `propam5553@gmail.com`
4. Click **Send**

**⚠️ Important Notes:**
- Must forward **as attachment**, not regular forward!
- Use REAL suspicious emails, not test/fake emails
- propam5553@gmail.com is the actual test account for this project

### For Analysts: Review Workflow

1. **Open Dashboard**
   - Navigate to `/forwarded-emails` page
   - View list of pending emails

2. **Select Email**
   - Click on email to see preview
   - Check sender, subject, date

3. **Analyze**
   - Click "Analyze" button
   - Wait 5-10 seconds for results

4. **Review Results**
   - Overall score: 0-100% (lower = more phishing)
   - Verdict: LEGITIMATE, SUSPICIOUS, PHISHING
   - 5 section scores with details
   - Risk factors list

5. **Take Action**
   - Mark as handled
   - Notify user
   - Add to blocklist (if phishing)
   - Create incident ticket

---

## 🆚 IMAP vs OAuth Comparison

| Feature | IMAP (New) | OAuth (Existing) |
|---------|-----------|------------------|
| **Setup Time** | 15 minutes | 2-3 hours |
| **Configuration** | App Password | Google Cloud Console |
| **User Action** | Forward as attachment | Auto-scan inbox |
| **Analyst Control** | Manual selection | Automated |
| **Gmail Quotas** | No API quotas | API rate limits |
| **Email Access** | Forwarded only | Full mailbox |
| **Best For** | User-reported phishing | Proactive scanning |

**Recommendation:** Use both!
- **IMAP** for user-reported suspicious emails (high priority)
- **OAuth** for automated scanning of all incoming emails

---

## 🐛 Troubleshooting

### Connection Fails

**Error:** "Authentication failed"
```
✓ Check App Password (no spaces, 16 characters)
✓ Regenerate App Password if needed
✓ Ensure 2FA is enabled on Gmail account
```

**Error:** "Connection timeout"
```
✓ Check internet connection
✓ Verify port 993 is open (firewall/antivirus)
✓ Try IMAP_HOST=imap.gmail.com vs IP address
```

### No Emails Found

**"No pending emails found"**
```
✓ Ensure email was forwarded **as attachment**
✓ Check IMAP_FOLDER setting (default: INBOX)
✓ Verify email arrived at IMAP_USER address
✓ Check if email is marked as read
```

### Analysis Fails

**"Failed to extract EML attachment"**
```
✓ Ensure forwarded **as attachment**, not regular forward
✓ Check email format (.eml or .msg)
✓ Try with different email client
```

### Performance Issues

**"Analysis too slow"**
```
✓ Check Redis connection (caching)
✓ Check MongoDB connection
✓ Verify network latency to external APIs
✓ Consider increasing server resources
```

---

## 📊 Monitoring

### Health Check
```bash
curl http://localhost:8000/api/v1/imap-emails/test-connection
```

### Logs
```bash
# Check IMAP service logs
tail -f logs/phishnet.log | grep "IMAP"

# Check analysis logs
tail -f logs/phishnet.log | grep "EnhancedPhishingAnalyzer"
```

### Metrics
```bash
# Pending emails count
curl http://localhost:8000/api/v1/imap-emails/pending | jq '.total'

# Analysis statistics
curl http://localhost:8000/api/v1/imap-emails/stats
```

---

## 🚀 Production Deployment

### Environment Variables
```bash
# Required
IMAP_ENABLED=true
IMAP_USER=phishnet@company.com
IMAP_PASSWORD=your_app_password

# Optional (defaults shown)
IMAP_HOST=imap.gmail.com
IMAP_PORT=993
IMAP_FOLDER=INBOX
IMAP_POLL_INTERVAL=60
```

### System Requirements
- Python 3.11+
- 2GB RAM minimum
- MongoDB running
- Redis running (optional, improves performance)

### Security Considerations
1. **App Password:** Treat like regular password, never commit to git
2. **IMAP Folder:** Create dedicated folder (e.g., "PhishNet Reports")
3. **Email Retention:** Set up auto-archive after analysis
4. **Rate Limiting:** Consider API rate limits for /analyze endpoint
5. **Email Notifications:** Configure SMTP for analyst notifications

### Scaling
- **Low Volume (<100 emails/day):** Single server, IMAP_POLL_INTERVAL=60
- **Medium Volume (<1000 emails/day):** Multiple workers, IMAP_POLL_INTERVAL=30
- **High Volume (>1000 emails/day):** Distributed workers, dedicated IMAP service

---

## 📚 Additional Resources

- **Full Documentation:** `docs/EMAIL_INTEGRATION_SOLUTION.md`
- **Implementation Details:** `docs/THEPHISH_INTEGRATION_COMPLETE.md`
- **Enhanced Analyzer:** `docs/ENHANCED_ANALYSIS_COMPLETE.md`
- **ThePhish Project:** https://github.com/emalderson/ThePhish

---

## ✅ Success Checklist

- [ ] Gmail App Password created
- [ ] .env file configured with IMAP settings
- [ ] test_imap_integration.py runs successfully
- [ ] Test email forwarded and detected
- [ ] Test email analyzed with results
- [ ] API endpoints tested (all 4 working)
- [ ] Frontend dashboard created (optional)
- [ ] User documentation distributed
- [ ] Analyst training completed
- [ ] Production deployment configured

---

## 🎉 You're Ready!

Your PhishNet instance now supports ThePhish-style email forwarding! Users can report suspicious emails in seconds, and analysts have full control over the review process.

**Need Help?**
- Check the full documentation in `docs/`
- Review code in `app/services/quick_imap.py`
- Test with `test_imap_integration.py`

**Happy Phishing Detection! 🎣🔒**
