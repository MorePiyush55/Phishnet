# 🔴 REAL EMAIL CONFIGURATION GUIDE
# For PhishNet IMAP Integration with propam5553@gmail.com

## ⚠️ IMPORTANT: Using REAL Emails, Not Test Data

This project uses **propam5553@gmail.com** as the actual test email account. This means:

✅ **DO:** Use REAL phishing/suspicious emails  
❌ **DON'T:** Use fake/test emails or mock data

---

## 📧 Email Account Setup

### Account: propam5553@gmail.com

This account should be used to:
1. **Receive forwarded suspicious emails** from users
2. **Store real phishing attempts** for analysis
3. **Test the Enhanced Phishing Analyzer** with actual threats

---

## 🚀 Quick Setup (5 Minutes)

### Step 1: Get Gmail App Password

1. Log in to **propam5553@gmail.com**
2. Go to: https://myaccount.google.com/security
3. Enable **2-Factor Authentication** (if not enabled)
4. Go to: https://myaccount.google.com/apppasswords
5. Select:
   - App: **Mail**
   - Device: **Other (PhishNet)**
6. Click **Generate**
7. Copy the **16-character password** (example: `abcd efgh ijkl mnop`)

### Step 2: Create .env File

Create `backend/.env` with:

```bash
# IMAP Configuration - REAL EMAIL ACCOUNT
IMAP_ENABLED=true
IMAP_HOST=imap.gmail.com
IMAP_PORT=993
IMAP_USER=propam5553@gmail.com
IMAP_PASSWORD=your_16_char_app_password_here
IMAP_FOLDER=INBOX
IMAP_POLL_INTERVAL=60

# MongoDB (Required)
MONGODB_URL=mongodb://localhost:27017
MONGODB_DB_NAME=phishnet

# Redis (Optional but recommended)
REDIS_URL=redis://localhost:6379/0
```

### Step 3: Enable IMAP in Gmail

1. Log in to **propam5553@gmail.com**
2. Go to **Settings** (gear icon) → **See all settings**
3. Click **Forwarding and POP/IMAP** tab
4. Under **IMAP access**, select **Enable IMAP**
5. Click **Save Changes**

---

## 📨 Where to Get Real Phishing Emails

### 1. Gmail Spam Folder
```
1. Open propam5553@gmail.com
2. Go to Spam folder
3. Select suspicious emails
4. Forward as attachment to propam5553@gmail.com
```

### 2. Email Security Alerts
- Real phishing attempts blocked by email filters
- Suspicious emails flagged by users
- Security team reports

### 3. Phishing Simulation Campaigns
- If you run phishing simulations
- Training emails sent to employees
- Known phishing templates

### 4. User-Reported Emails
- Employees who report suspicious emails
- Forward their reports to propam5553@gmail.com
- Analyze real-world threats

### 5. Public Phishing Databases
- PhishTank (https://phishtank.org/)
- OpenPhish (https://openphish.com/)
- Download .eml files and forward them

---

## 🔄 Testing Workflow with Real Emails

### For Developers/Testers:

1. **Find a Real Phishing Email**
   - Check spam folder in propam5553@gmail.com
   - Or forward from your own spam folder

2. **Forward as Attachment**
   ```
   1. Open the suspicious email
   2. Click More (⋮) → Forward as attachment
   3. To: propam5553@gmail.com
   4. Subject: [Optional] Add note about this email
   5. Send
   ```

3. **Run Test Script**
   ```powershell
   cd backend
   python test_imap_integration.py
   ```

4. **Review Results**
   - Check phishing score (0-100%)
   - Review risk factors
   - Validate detection accuracy

---

## 📊 Expected Test Results

### Real Phishing Email Example:
```
Subject: "Your account will be suspended"
From: security@paypa1.com (note the "1" instead of "l")

Expected Analysis:
- Overall Score: 15-30% (PHISHING)
- Sender: Low score (domain mismatch)
- Content: Low score (urgency keywords)
- Links: Low score (suspicious URLs)
- Authentication: Low score (SPF fail)
- Attachments: Varies by email
```

### Real Legitimate Email Example:
```
Subject: "Your Amazon order has shipped"
From: auto-confirm@amazon.com

Expected Analysis:
- Overall Score: 80-100% (LEGITIMATE)
- Sender: High score (verified domain)
- Content: High score (normal language)
- Links: High score (HTTPS, amazon.com)
- Authentication: High score (SPF/DKIM pass)
- Attachments: Safe types
```

---

## 🧪 Testing Checklist

Before running tests, ensure you have:

- [ ] Gmail App Password for propam5553@gmail.com
- [ ] IMAP enabled in Gmail settings
- [ ] `.env` file created with correct credentials
- [ ] At least 2-3 REAL phishing emails forwarded
- [ ] At least 1-2 REAL legitimate emails forwarded
- [ ] MongoDB running (for storing results)
- [ ] Redis running (optional, for caching)

---

## 🔒 Security Best Practices

### 1. App Password Security
- ✅ Never commit `.env` to git
- ✅ Use App Password, not regular password
- ✅ Regenerate if compromised
- ✅ Store securely (password manager)

### 2. Email Account Security
- ✅ Enable 2-Factor Authentication
- ✅ Monitor for unauthorized access
- ✅ Use dedicated account (not personal)
- ✅ Regularly review connected apps

### 3. Phishing Email Handling
- ✅ Don't click links in phishing emails
- ✅ Don't download attachments from suspicious emails
- ✅ Use sandboxed environment for testing
- ✅ Archive analyzed emails

---

## 📈 Continuous Testing Strategy

### Daily Testing:
1. Check propam5553@gmail.com for new spam
2. Forward 2-3 suspicious emails
3. Run analysis
4. Review detection accuracy

### Weekly Testing:
1. Collect 10+ real phishing emails
2. Batch analyze using API
3. Calculate detection rate
4. Review false positives/negatives

### Monthly Testing:
1. Update phishing keyword database
2. Test with latest phishing campaigns
3. Tune analyzer weights if needed
4. Document improvements

---

## 🐛 Troubleshooting with Real Emails

### Issue: "No emails found"
**Check:**
- Are emails in INBOX folder? (not Spam)
- Were emails forwarded "as attachment"?
- Is IMAP_FOLDER set correctly in .env?

### Issue: "Analysis shows 100% for phishing email"
**This is EXPECTED if:**
- Email is from a legitimate company's official domain
- SPF/DKIM/DMARC all pass
- No suspicious keywords found
- All links are HTTPS to legitimate domains

**The analyzer is working correctly!** Not all spam is phishing.

### Issue: "Analysis shows 0% for legitimate email"
**Check if email has:**
- Suspicious sender domain
- Urgency keywords (ACT NOW, VERIFY, SUSPENDED)
- Failed SPF/DKIM checks
- Suspicious links or redirects

**This might be a false positive - review and tune if needed.**

---

## 📊 Sample Test Scenarios

### Scenario 1: PayPal Phishing
```
Email: propam5553@gmail.com receives forwarded email
From: security@paypa1-secure.com
Subject: Urgent: Verify Your Account
Content: "Click here within 24 hours or account suspended"
Link: http://paypal-verify.sketchy-domain.com

Expected Result:
- Score: 15-25% (PHISHING)
- Sender: FAIL (domain mismatch)
- Content: FAIL (urgency keywords)
- Links: FAIL (HTTP, suspicious domain)
- Authentication: FAIL (SPF fail)
```

### Scenario 2: Legitimate Amazon Email
```
Email: propam5553@gmail.com receives forwarded email
From: ship-confirm@amazon.com
Subject: Your order has shipped
Content: "Track your package here"
Link: https://www.amazon.com/tracking/123456

Expected Result:
- Score: 85-95% (LEGITIMATE)
- Sender: PASS (verified domain)
- Content: PASS (normal language)
- Links: PASS (HTTPS, legitimate domain)
- Authentication: PASS (SPF/DKIM/DMARC pass)
```

---

## ✅ Verification Steps

Run these commands to verify everything works:

```powershell
# 1. Test IMAP connection
cd backend
python test_imap_integration.py

# 2. Start FastAPI server
uvicorn app.main:app --reload

# 3. Test API endpoints (in another terminal)
# Test connection
curl http://localhost:8000/api/v1/imap-emails/test-connection

# List pending emails
curl http://localhost:8000/api/v1/imap-emails/pending

# Analyze email (replace UID)
curl -X POST http://localhost:8000/api/v1/imap-emails/analyze/12345

# Get statistics
curl http://localhost:8000/api/v1/imap-emails/stats
```

---

## 🎯 Success Criteria

Your setup is working correctly when:

✅ IMAP connection test passes  
✅ Real phishing emails are detected (score < 30%)  
✅ Real legitimate emails pass (score > 70%)  
✅ Analysis completes in < 10 seconds  
✅ Results are stored in MongoDB  
✅ API endpoints respond correctly  

---

## 📞 Need Help?

**Common Issues:**
1. **Can't connect to IMAP:** Check App Password, enable IMAP
2. **No emails found:** Forward "as attachment", check folder
3. **Wrong analysis results:** Verify using real emails, not test data

**Documentation:**
- Quick Start: `backend/IMAP_QUICK_START.md`
- Technical Details: `docs/EMAIL_INTEGRATION_SOLUTION.md`
- Test Script: `backend/test_imap_integration.py`

---

## 🎉 Ready to Test!

You're all set to test PhishNet with **real phishing emails** using **propam5553@gmail.com**!

**Remember:**
- ✅ Use REAL emails only
- ✅ Forward as attachment
- ✅ Never click links in phishing emails
- ✅ Analyze, learn, improve!

**Happy Real-World Testing! 🔒🎣**
