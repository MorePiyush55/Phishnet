# PhishNet IMAP Email Forwarding Guide

## Overview

PhishNet supports **IMAP-based email forwarding** - a simple way for users to report suspicious emails. Users forward suspicious emails to a PhishNet inbox, which automatically analyzes them and sends back a report.

---

## How It Works

```
User                    PhishNet                     Analysis
┌─────────┐  Forward   ┌─────────────┐  Poll/Fetch  ┌──────────────┐
│ Receives│ ────────── │  PhishNet   │ ──────────── │  5-Module    │
│ Phishing│   Email    │  Inbox      │              │  Analyzer    │
│ Email   │            │ (Gmail)     │              │              │
└─────────┘            └─────────────┘              └──────────────┘
                                                           │
                              ┌─────────────────────────────┘
                              v
┌─────────┐  Reply     ┌─────────────┐   Store     ┌──────────────┐
│  User   │ ◀──────────│  Brevo/     │ ◀───────────│  MongoDB     │
│ Inbox   │  Report    │  Resend API │   Results   │  Storage     │
└─────────┘            └─────────────┘              └──────────────┘
```

**Flow:**
1. User forwards suspicious email to `phishnet.ai@gmail.com`
2. IMAP service polls inbox every 30 seconds
3. New emails are fetched and analyzed
4. Results sent back via email (Brevo/Resend API)
5. Analysis stored in MongoDB for deduplication

---

## Quick Setup (15 Minutes)

### Step 1: Create Gmail App Password

1. Log in to your PhishNet Gmail account (e.g., `phishnet.ai@gmail.com`)
2. Go to https://myaccount.google.com/security
3. Enable **2-Factor Authentication** if not already enabled
4. Go to https://myaccount.google.com/apppasswords
5. Select app: "Mail", device: "Other (PhishNet)"
6. Click "Generate"
7. **Copy the 16-character password** (e.g., `abcd efgh ijkl mnop` → use without spaces)

### Step 2: Enable IMAP in Gmail

1. Open Gmail Settings → **See all settings**
2. Go to **Forwarding and POP/IMAP** tab
3. Select **Enable IMAP**
4. Click **Save Changes**

### Step 3: Configure Environment Variables

Add to Render Dashboard (or `.env` for local):

```env
# IMAP Configuration
IMAP_ENABLED=True
IMAP_HOST=imap.gmail.com
IMAP_USER=phishnet.ai@gmail.com
IMAP_PASSWORD=your_16_char_app_password
IMAP_FOLDER=INBOX

# Email Reply Service (choose one)
BREVO_API_KEY=your_brevo_api_key
# OR
RESEND_API_KEY=your_resend_api_key
```

### Step 4: Test Connection

Visit: `https://your-backend.onrender.com/api/v1/imap-emails/test-connection`

Expected response:
```json
{
  "success": true,
  "status": "connected",
  "folder": "INBOX"
}
```

---

## API Endpoints

### Test Connection
```http
GET /api/v1/imap-emails/test-connection
```

### List Pending Emails
```http
GET /api/v1/imap-emails/pending?limit=20
```

### Analyze Email
```http
POST /api/v1/imap-emails/analyze/{uid}
```

### Manual Poll Trigger
```http
POST /api/v1/imap/poll
```

---

## Analysis Pipeline

Each forwarded email goes through a **5-module analysis**:

| Module | Score Weight | Checks |
|--------|-------------|--------|
| **Sender Analysis** | 20% | Email/domain mismatch, spoofing indicators |
| **Content Analysis** | 25% | Urgency keywords, grammar, suspicious patterns |
| **Link Analysis** | 25% | Malicious URLs, redirects, suspicious TLDs |
| **Authentication** | 15% | SPF, DKIM, DMARC verification |
| **Attachment Analysis** | 15% | Dangerous extensions, executable files |

**Verdicts:**
- 🚨 **PHISHING** (0-40 score) - Delete immediately
- ⚠️ **SUSPICIOUS** (41-70 score) - Verify sender before acting
- ✅ **SAFE** (71-100 score) - Likely legitimate

---

## User Instructions

### How to Forward Suspicious Emails

**Desktop (Gmail/Outlook):**
1. Open the suspicious email
2. Click **More (⋮)** → **Forward as attachment** (recommended)
   - Or just click **Forward**
3. Send to: `phishnet.ai@gmail.com`
4. Wait 1-2 minutes for analysis report

**Mobile (Gmail App):**
1. Open the suspicious email
2. Tap **⋮** → **Forward**
3. Send to: `phishnet.ai@gmail.com`
4. Check your inbox for the report

**iPhone Mail:**
1. Open the suspicious email
2. Tap **Reply arrow** → **Forward**
3. Send to: `phishnet.ai@gmail.com`

---

## Configuration Options

| Variable | Default | Description |
|----------|---------|-------------|
| `IMAP_ENABLED` | `False` | Enable IMAP polling |
| `IMAP_HOST` | `imap.gmail.com` | IMAP server |
| `IMAP_USER` | - | Gmail address |
| `IMAP_PASSWORD` | - | App Password (16 chars) |
| `IMAP_FOLDER` | `INBOX` | Folder to monitor |
| `IMAP_POLL_INTERVAL` | `60` | Seconds between polls |
| `IMAP_BATCH_SIZE` | `50` | Max emails per poll |

---

## Troubleshooting

### "Found 0 recent emails"
- Check IMAP credentials are correct
- Verify IMAP is enabled in Gmail settings
- Check App Password (no spaces)

### "Authentication Failed"
- Regenerate App Password at https://myaccount.google.com/apppasswords
- Ensure 2FA is enabled on the Gmail account
- Update `IMAP_PASSWORD` in Render environment

### "Email analyzed but no reply received"
- Check `BREVO_API_KEY` or `RESEND_API_KEY` is configured
- Verify the email service account is activated
- Check Render logs for email sending errors

### Rate Limiting (429 errors)
- Gemini AI has 15 requests/minute limit
- System uses fallback rule-based explanations
- Consider upgrading to paid Gemini tier

---

## Email Reply Service Setup

### Option 1: Brevo (Recommended - 300 emails/day free)

1. Sign up at https://brevo.com
2. Go to SMTP & API → API Keys
3. Create new API key
4. Add to Render: `BREVO_API_KEY=xkeysib-...`

### Option 2: Resend (100 emails/day free)

1. Sign up at https://resend.com
2. Create API key
3. **Important**: Verify a domain to send to external recipients
4. Add to Render: `RESEND_API_KEY=re_...`

---

## Security Considerations

- **Data Retention**: Analyzed emails stored in MongoDB for deduplication
- **Privacy**: Only email metadata and analysis results are stored, not full email content
- **Access**: App Password only allows IMAP access, not full Google account
- **Encryption**: All connections use TLS/SSL

---

## Architecture Details

### Components

| Component | File | Description |
|-----------|------|-------------|
| IMAP Service | `app/services/quick_imap.py` | Fetches emails from inbox |
| Polling Worker | `app/workers/email_polling_worker.py` | Background polling loop |
| Orchestrator | `app/services/ondemand_orchestrator.py` | Analysis pipeline |
| Email Sender | `app/services/email_sender.py` | Sends reply reports |
| API Routes | `app/api/v1/imap_emails.py` | REST endpoints |

### Database Schema

```javascript
// MongoDB: forwarded_email_analyses collection
{
  "user_id": "piyushmore5553@gmail.com",
  "forwarded_by": "piyushmore5553@gmail.com",
  "original_sender": "suspicious@phishing.com",
  "original_subject": "Urgent: Verify Your Account",
  "threat_score": 0.85,
  "risk_level": "PHISHING",
  "analysis_result": {
    "verdict": "PHISHING",
    "score": 15,
    "confidence": 0.85,
    "risk_factors": ["spoofed sender", "urgency keywords", "suspicious links"]
  },
  "email_metadata": {
    "message_id": "<abc123@mail.gmail.com>",
    "uid": "52"
  },
  "reply_sent": true,
  "reply_sent_at": "2025-12-25T06:44:42Z",
  "created_at": "2025-12-25T06:44:39Z"
}
```
