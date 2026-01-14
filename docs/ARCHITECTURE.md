# PhishNet Architecture

## Overview

PhishNet is an AI-powered phishing email detection system with a modular architecture for analyzing suspicious emails.

---

## System Architecture

```
┌──────────────────────────────────────────────────────────────────────┐
│                         FRONTEND (Vercel)                             │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  │
│  │   Dashboard │  │   Gmail     │  │   Analysis  │  │   Chrome    │  │
│  │   (React)   │  │   OAuth     │  │   Results   │  │  Extension  │  │
│  └─────────────┘  └─────────────┘  └─────────────┘  └─────────────┘  │
└──────────────────────────────────────────────────────────────────────┘
                                    ↓ API
┌──────────────────────────────────────────────────────────────────────┐
│                         BACKEND (Render)                              │
│  ┌─────────────────────────────────────────────────────────────────┐ │
│  │                      FastAPI Application                         │ │
│  │  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────────────┐ │ │
│  │  │  Auth    │  │  IMAP    │  │ Analysis │  │  Email Sender    │ │ │
│  │  │  Router  │  │  Router  │  │  Router  │  │  (Brevo/Resend)  │ │ │
│  │  └──────────┘  └──────────┘  └──────────┘  └──────────────────┘ │ │
│  └─────────────────────────────────────────────────────────────────┘ │
│  ┌─────────────────────────────────────────────────────────────────┐ │
│  │                     Analysis Pipeline                            │ │
│  │  ┌────────────────────────────────────────────────────────────┐ │ │
│  │  │              Enhanced Phishing Analyzer                     │ │ │
│  │  │  ┌──────┐ ┌───────┐ ┌──────┐ ┌──────┐ ┌────────────────┐  │ │ │
│  │  │  │Sender│ │Content│ │ Link │ │ Auth │ │  Attachment    │  │ │ │
│  │  │  │ 20%  │ │  25%  │ │ 25%  │ │ 15%  │ │     15%        │  │ │ │
│  │  │  └──────┘ └───────┘ └──────┘ └──────┘ └────────────────┘  │ │ │
│  │  └────────────────────────────────────────────────────────────┘ │ │
│  │  ┌────────────────────────────────────────────────────────────┐ │ │
│  │  │                  AI Interpretation (Gemini)                 │ │ │
│  │  └────────────────────────────────────────────────────────────┘ │ │
│  └─────────────────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────────────────┘
                                    ↓
┌──────────────────────────────────────────────────────────────────────┐
│                        EXTERNAL SERVICES                              │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  │
│  │  MongoDB    │  │  Gmail      │  │  VirusTotal │  │  AbuseIPDB  │  │
│  │  Atlas      │  │  IMAP       │  │  (Malware)  │  │  (IP Rep)   │  │
│  └─────────────┘  └─────────────┘  └─────────────┘  └─────────────┘  │
└──────────────────────────────────────────────────────────────────────┘
```

---

## Project Structure

```
Phishnet/
├── backend/                    # FastAPI Python backend
│   ├── app/
│   │   ├── api/               # REST API endpoints
│   │   │   └── v1/            # API version 1
│   │   ├── config/            # Settings, logging
│   │   ├── models/            # MongoDB models (Beanie ODM)
│   │   ├── services/          # Business logic
│   │   │   ├── quick_imap.py              # IMAP email fetching
│   │   │   ├── ondemand_orchestrator.py   # Analysis pipeline
│   │   │   ├── enhanced_phishing_analyzer.py  # 5-module analyzer
│   │   │   ├── gemini.py                  # AI interpretation
│   │   │   └── email_sender.py            # Reply service
│   │   └── workers/           # Background tasks
│   │       └── email_polling_worker.py    # IMAP polling loop
│   ├── main.py                # Application entry point
│   └── requirements.txt       # Python dependencies
│
├── frontend/                  # React TypeScript frontend
│   ├── src/
│   │   ├── components/        # React components
│   │   ├── pages/             # Page components
│   │   ├── hooks/             # Custom React hooks
│   │   └── context/           # React context providers
│   └── package.json           # Node dependencies
│
└── docs/                      # Documentation
```

---

## Analysis Pipeline

### 5-Module Enhanced Phishing Analyzer

| Module | Weight | What It Checks |
|--------|--------|----------------|
| **Sender Analysis** | 20% | Display name vs email mismatch, spoofing patterns, free email domains |
| **Content Analysis** | 25% | Urgency keywords, grammar errors, suspicious phrases, pressure tactics |
| **Link Analysis** | 25% | Malicious URLs, redirects, URL shorteners, suspicious TLDs, VirusTotal |
| **Authentication** | 15% | SPF, DKIM, DMARC verification results |
| **Attachment Analysis** | 15% | Dangerous extensions (.exe, .js), double extensions, macro files |

### Scoring System

```
Total Score = Σ (Module Score × Module Weight)

Score 0-40:   PHISHING    🚨 High risk
Score 41-70:  SUSPICIOUS  ⚠️ Medium risk  
Score 71-100: SAFE        ✅ Low risk
```

### Analysis Flow

```
1. Email Received (IMAP)
         ↓
2. Parse Email (Headers, Body, Attachments)
         ↓
3. Run 5 Analysis Modules (Parallel)
         ↓
4. Calculate Weighted Score
         ↓
5. Determine Verdict
         ↓
6. AI Interpretation (Gemini - Optional)
         ↓
7. Store in MongoDB
         ↓
8. Send Reply Email (Brevo/Resend)
```

---

## API Endpoints

### Authentication
- `POST /api/v1/auth/login` - User login
- `POST /api/v1/auth/register` - User registration
- `GET /api/v1/auth/gmail/callback` - Gmail OAuth callback

### IMAP Email Analysis
- `GET /api/v1/imap-emails/test-connection` - Test IMAP connection
- `GET /api/v1/imap-emails/pending` - List unanalyzed emails
- `POST /api/v1/imap-emails/analyze/{uid}` - Analyze specific email
- `POST /api/v1/imap/poll` - Trigger manual poll

### Analysis
- `POST /api/v1/analyze/email` - Analyze email content directly
- `GET /api/v1/analysis/{id}` - Get analysis results

### Health
- `GET /health` - Service health check
- `GET /docs` - Swagger API documentation

---

## Database Schema

### MongoDB Collections

**forwarded_email_analyses**
```javascript
{
  "_id": ObjectId,
  "user_id": "user@email.com",
  "forwarded_by": "user@email.com",
  "original_sender": "suspicious@phishing.com",
  "original_subject": "Urgent Action Required",
  "threat_score": 0.85,
  "risk_level": "PHISHING",
  "analysis_result": {
    "verdict": "PHISHING",
    "score": 15,
    "confidence": 0.85,
    "risk_factors": ["spoofed sender", "urgency"]
  },
  "email_metadata": {
    "message_id": "<abc123@mail.com>",
    "uid": "52"
  },
  "reply_sent": true,
  "created_at": ISODate
}
```

**users**
```javascript
{
  "_id": ObjectId,
  "email": "user@email.com",
  "hashed_password": "bcrypt_hash",
  "oauth_provider": "google",
  "created_at": ISODate
}
```

---

## Background Workers

### Email Polling Worker

```python
# Runs every 30 seconds
1. Connect to Gmail IMAP
2. Fetch recent emails (limit 50)
3. Check MongoDB for already-processed (by message_id)
4. Process new emails through analysis pipeline
5. Send reply with results
6. Store in MongoDB for deduplication
```

---

## Security Features

- **JWT Authentication**: Token-based auth with refresh tokens
- **OAuth 2.0**: Google/Gmail integration
- **Rate Limiting**: API request throttling
- **CORS**: Configured for allowed origins
- **Input Validation**: Pydantic models
- **Secret Management**: Environment variables

---

## Scalability Considerations

### Current Architecture (Free Tier)
- Single Render instance
- MongoDB Atlas M0 (512MB)
- No Redis (rate limiting disabled)

### Production Scaling
- Horizontal scaling with multiple Render instances
- Redis for caching and rate limiting
- MongoDB Atlas M10+ for better performance
- Background job queue (Celery + Redis)
