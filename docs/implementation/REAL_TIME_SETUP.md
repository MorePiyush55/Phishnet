# Real-Time Email Scanning Setup Guide

## 🚀 Quick Start for Real-Time Email Scanning

This guide will help you set up and test the real-time email scanning functionality when users sign in to your PhishNet website.

## 📋 Prerequisites

1. **Python Environment**: Ensure you have Python 3.8+ with virtual environment
2. **Gmail API Setup**: Google Cloud Project with Gmail API enabled
3. **Redis Server**: For background task processing
4. **Database**: PostgreSQL or SQLite for development

## ⚙️ Initial Setup

### 1. Environment Configuration

Create `.env` file with:
```bash
# Copy from env.example and update
cp env.example .env

# Edit .env with your values:
SECRET_KEY=your-very-long-secret-key-here
DATABASE_URL=postgresql://user:pass@localhost/phishnet
REDIS_URL=redis://localhost:6379/0

# Gmail API Credentials (get from Google Cloud Console)
GMAIL_CLIENT_ID=your-gmail-client-id
GMAIL_CLIENT_SECRET=your-gmail-client-secret
GOOGLE_CLOUD_PROJECT=your-project-id

# Security Settings
ACCESS_TOKEN_EXPIRE_MINUTES=30
REFRESH_TOKEN_EXPIRE_DAYS=7
ENABLE_CONTENT_SANITIZATION=true
ENABLE_LINK_REWRITING=true
```

### 2. Database Setup

```bash
# Initialize database
python scripts/init_db.py

# Run migrations (if using Alembic)
alembic upgrade head
```

### 3. Start Background Services

```bash
# Terminal 1: Start Redis (if not running as service)
redis-server

# Terminal 2: Start Celery worker for email processing
celery -A app.main.celery worker --loglevel=info

# Terminal 3: Start Celery beat for scheduled tasks
celery -A app.main.celery beat --loglevel=info
```

### 4. Start the FastAPI Server

```bash
# Terminal 4: Start the web server
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

## 🔑 Gmail API Setup

### 1. Google Cloud Console Setup

1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Create a new project or select existing
3. Enable Gmail API
4. Create OAuth 2.0 credentials
5. Add your domain to authorized origins

### 2. OAuth Consent Screen

Configure the consent screen with:
- Application name: "PhishNet Email Scanner"
- User support email: your-email@domain.com
- Scopes: 
  - `https://www.googleapis.com/auth/gmail.readonly`
  - `https://www.googleapis.com/auth/gmail.modify`

### 3. Download Credentials

Download the OAuth client credentials JSON and save as `gmail_credentials.json`

## 🧪 Testing Real-Time Email Scanning

### 1. User Registration & Login

```bash
# Test user registration
curl -X POST http://localhost:8000/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test@example.com",
    "password": "SecurePass123!",
    "full_name": "Test User",
    "role": "analyst"
  }'

# Test login to get tokens
curl -X POST http://localhost:8000/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test@example.com",
    "password": "SecurePass123!"
  }'
```

### 2. Gmail Integration Flow

```bash
# 1. Get Gmail authorization URL
curl -X GET http://localhost:8000/gmail/auth-url \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"

# 2. User visits the URL and authorizes
# 3. Handle the callback with authorization code
curl -X POST http://localhost:8000/gmail/callback \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"code": "AUTHORIZATION_CODE_FROM_GOOGLE"}'

# 4. Start email monitoring
curl -X POST http://localhost:8000/gmail/start-monitoring \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```

### 3. Real-Time Monitoring Test

```bash
# Check monitoring status
curl -X GET http://localhost:8000/emails/stats/summary \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"

# Get real-time email list
curl -X GET http://localhost:8000/emails/?status=pending \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"

# Test manual email scan
curl -X POST http://localhost:8000/gmail/sync \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```

## 🌐 Frontend Integration

### WebSocket Connection for Real-Time Updates

```javascript
// Connect to WebSocket for real-time notifications
const ws = new WebSocket('ws://localhost:8000/ws');

ws.onmessage = function(event) {
    const data = JSON.parse(event.data);
    if (data.type === 'new_email') {
        // Update email list in real-time
        updateEmailList(data.email);
    } else if (data.type === 'threat_detected') {
        // Show threat alert
        showThreatAlert(data.email, data.risk_score);
    }
};

// Send authentication token
ws.send(JSON.stringify({
    type: 'auth',
    token: 'YOUR_ACCESS_TOKEN'
}));
```

### React Component Example

```jsx
// EmailMonitoringDashboard.jsx
import React, { useState, useEffect } from 'react';

function EmailMonitoringDashboard() {
    const [emails, setEmails] = useState([]);
    const [isMonitoring, setIsMonitoring] = useState(false);

    useEffect(() => {
        // Connect to WebSocket for real-time updates
        const ws = new WebSocket('ws://localhost:8000/ws');
        
        ws.onmessage = (event) => {
            const data = JSON.parse(event.data);
            if (data.type === 'new_email') {
                setEmails(prev => [data.email, ...prev]);
            }
        };

        return () => ws.close();
    }, []);

    const startMonitoring = async () => {
        const response = await fetch('/gmail/start-monitoring', {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${accessToken}`,
            },
        });
        if (response.ok) {
            setIsMonitoring(true);
        }
    };

    return (
        <div>
            <h2>Real-Time Email Monitoring</h2>
            {!isMonitoring ? (
                <button onClick={startMonitoring}>
                    Start Email Monitoring
                </button>
            ) : (
                <div>
                    <p>✅ Monitoring active - scanning emails in real-time</p>
                    <EmailList emails={emails} />
                </div>
            )}
        </div>
    );
}
```

## 🔍 Monitoring & Debugging

### Health Check Endpoints

```bash
# Check system health
curl http://localhost:8000/health

# Check Gmail connection status
curl -X GET http://localhost:8000/gmail/status \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"

# Check background task status
curl http://localhost:8000/admin/tasks/status
```

### Logs to Monitor

1. **FastAPI logs**: Application startup and API requests
2. **Celery logs**: Background email processing
3. **Gmail API logs**: API rate limits and errors
4. **Security logs**: Authentication attempts and failures

## 🚨 Troubleshooting

### Common Issues

1. **Gmail API Quota Exceeded**
   - Solution: Implement exponential backoff
   - Check Google Cloud Console quota usage

2. **WebSocket Connection Failures**
   - Verify CORS settings
   - Check firewall configuration

3. **Background Tasks Not Processing**
   - Ensure Redis is running
   - Check Celery worker status

4. **Token Refresh Failures**
   - Verify Gmail credentials
   - Check token expiration handling

### Debug Mode

Run with debug logging:
```bash
PHISHNET_LOG_LEVEL=DEBUG uvicorn app.main:app --reload
```

## 📈 Performance Considerations

1. **Rate Limiting**: Gmail API has quotas (250 quota units per user per second)
2. **Batch Processing**: Process emails in batches for efficiency
3. **Caching**: Use Redis for frequently accessed data
4. **WebSocket Scaling**: Consider using Redis pub/sub for multiple instances

## 🔐 Security Checklist

- [ ] HTTPS enabled in production
- [ ] JWT tokens use strong secrets
- [ ] Gmail credentials securely stored
- [ ] Content sanitization enabled
- [ ] Rate limiting configured
- [ ] CORS properly configured
- [ ] Security headers enabled
- [ ] Input validation on all endpoints

Your PhishNet system is now ready for real-time email scanning! Users can sign in, connect their Gmail accounts, and receive immediate alerts about potential phishing threats.
