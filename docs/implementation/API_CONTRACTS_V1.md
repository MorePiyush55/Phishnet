# PhishNet API v1 - Complete Contract Documentation

## 🚀 API Overview

PhishNet API v1 provides standardized, versioned endpoints for email security analysis with consistent request/response patterns and comprehensive functionality.

**Base URL**: `http://localhost:8000/api/v1`

## 🔐 Authentication

### Login
**Contract**: `POST /api/v1/auth/login`

```json
// Request
{
  "email": "string",
  "password": "string"
}

// Response
{
  "access_token": "string",
  "refresh_token": "string", 
  "user": {
    "id": 1,
    "email": "admin@company.com",
    "name": "Admin User",
    "role": "admin",
    "is_active": true,
    "created_at": "2025-08-14T10:00:00Z"
  }
}
```

### Refresh Token
**Contract**: `POST /api/v1/auth/refresh`

```json
// Request
{
  "refresh_token": "string"
}

// Response
{
  "access_token": "string"
}
```

### Logout
**Contract**: `POST /api/v1/auth/logout`

```json
// Request
{
  "refresh_token": "string"
}

// Response
{
  "ok": true
}
```

## 📧 Email Management

### List Emails
**Contract**: `GET /api/v1/emails?status=&q=&page=&limit=`

**Query Parameters**:
- `status`: Filter by status (`pending`, `analyzed`, `quarantined`, `safe`)
- `q`: Search query for subject, sender, or content
- `page`: Page number (default: 1)
- `limit`: Items per page (default: 50, max: 100)

```json
// Response
{
  "items": [
    {
      "id": 123,
      "subject": "Urgent: Account Verification Required",
      "sender": "security@paypal-verify.com",
      "received_at": "2025-08-14T10:30:00Z",
      "status": "quarantined",
      "risk_score": 0.85,
      "risk_level": "high"
    }
  ],
  "total": 1247,
  "page": 1,
  "limit": 50,
  "has_next": true
}
```

### Email Detail
**Contract**: `GET /api/v1/emails/{id}`

```json
// Response
{
  "id": 123,
  "subject": "Urgent: Account Verification Required",
  "sender": "security@paypal-verify.com",
  "recipient": "user@company.com",
  "received_at": "2025-08-14T10:30:00Z",
  "status": "quarantined",
  "risk_score": 0.85,
  "risk_level": "high",
  "confidence": 0.95,
  "body_text": "Please verify your account...",
  "body_html": "<p>Please verify your account...</p>",
  "attachments": [],
  "links": [
    {
      "url": "https://paypal-verify.com/login",
      "risk_level": "high",
      "reasons": ["typosquatting", "suspicious_domain"]
    }
  ],
  "ai_analysis": {
    "classification": "phishing",
    "confidence": 0.95,
    "reasons": ["credential_harvesting", "urgency_tactics"]
  },
  "threat_intel": {
    "domain_reputation": "malicious",
    "ip_reputation": "suspicious"
  },
  "last_analyzed": "2025-08-14T10:31:00Z"
}
```

### Quarantine Email
**Contract**: `POST /api/v1/emails/{id}/quarantine`

```json
// Response
{
  "success": true,
  "message": "Email quarantined successfully",
  "action": "quarantine", 
  "email_id": 123,
  "timestamp": "2025-08-14T10:35:00Z"
}
```

### Rescan Email
**Contract**: `POST /api/v1/emails/{id}/rescan`

```json
// Response
{
  "job_id": "550e8400-e29b-41d4-a716-446655440000",
  "status": "queued",
  "message": "Email queued for re-analysis",
  "email_id": 123,
  "timestamp": "2025-08-14T10:36:00Z"
}
```

## 🔗 Link Analysis

### Email Links
**Contract**: `GET /api/v1/emails/{id}/links`

```json
// Response
{
  "email_id": 123,
  "links": [
    {
      "original": "https://paypal-verify.com/login",
      "final": "https://malicious-site.ru/steal",
      "risk": "high",
      "reasons": ["typosquatting", "redirect_chain", "malicious_domain"],
      "chain": [
        "https://paypal-verify.com/login",
        "https://bit.ly/abc123", 
        "https://malicious-site.ru/steal"
      ],
      "analysis_timestamp": "2025-08-14T10:31:00Z"
    }
  ],
  "total_links": 3,
  "high_risk_count": 1
}
```

### Ad-hoc Link Analysis
**Contract**: `POST /api/v1/links/analyze`

```json
// Request
{
  "url": "https://suspicious-domain.com/login"
}

// Response
{
  "url": "https://suspicious-domain.com/login",
  "final_url": "https://suspicious-domain.com/login",
  "risk_score": 0.72,
  "risk_level": "high",
  "reasons": ["typosquatting", "no_ssl", "new_domain"],
  "redirect_chain": ["https://suspicious-domain.com/login"],
  "domain_reputation": {
    "virustotal": {"detections": 5, "total": 89},
    "abuseipdb": {"confidence": 75}
  },
  "threat_intel": {
    "category": "phishing",
    "first_seen": "2025-08-13T00:00:00Z"
  },
  "analysis_timestamp": "2025-08-14T10:40:00Z"
}
```

## 🧠 Analysis & Intelligence

### Run Email Analysis
**Contract**: `POST /api/v1/analysis/{id}`

**Query Parameters**:
- `force_refresh`: Boolean to bypass cache (default: false)

```json
// Response
{
  "email_id": 123,
  "ai_analysis": {
    "classification": "phishing",
    "confidence": 0.95,
    "reasoning": "Email contains credential harvesting indicators...",
    "features": {
      "urgency_keywords": 0.8,
      "suspicious_links": 1.0,
      "sender_reputation": 0.1
    }
  },
  "threat_intel": {
    "domain_reputation": {
      "virustotal": {"malicious": 5, "clean": 0},
      "abuseipdb": {"confidence": 85}
    },
    "ip_reputation": {
      "source": "192.168.1.100",
      "reputation": "suspicious"
    }
  },
  "risk_score": 0.85,
  "risk_level": "high",
  "confidence": 0.95,
  "analysis_timestamp": "2025-08-14T10:31:00Z",
  "processing_time_ms": 2847
}
```

### Threat Intelligence Lookup
**Contract**: `GET /api/v1/intel/{indicator}`

**Query Parameters**:
- `indicator_type`: Type of indicator (`auto`, `domain`, `ip`, `url`, `hash`)

```json
// Response
{
  "indicator": "paypal-verify.com",
  "source": "multiple",
  "reputation": "malicious",
  "details": {
    "virustotal": {
      "detections": 5,
      "total_scans": 89,
      "categories": ["phishing", "malware"]
    },
    "abuseipdb": {
      "confidence": 85,
      "reports": 23,
      "last_reported": "2025-08-14T09:00:00Z"
    }
  },
  "last_updated": "2025-08-14T10:42:00Z"
}
```

## 📊 Audit & System

### Audit Logs
**Contract**: `GET /api/v1/audits?actor=&action=&from=&to=`

**Query Parameters**:
- `actor`: Filter by user email or "system"
- `action`: Filter by action type
- `from`: Start date (YYYY-MM-DD)
- `to`: End date (YYYY-MM-DD)
- `page`: Page number (default: 1)
- `limit`: Items per page (default: 50, max: 100)

```json
// Response
{
  "items": [
    {
      "id": 1,
      "timestamp": "2025-08-14T10:35:00Z",
      "actor": "admin@company.com",
      "action": "email_quarantined",
      "resource_type": "email",
      "resource_id": 123,
      "details": {
        "reason": "high_risk_score",
        "score": 0.95
      },
      "ip_address": "192.168.1.100",
      "user_agent": "Mozilla/5.0..."
    }
  ],
  "total": 1247,
  "page": 1,
  "limit": 50,
  "has_next": true
}
```

### System Health
**Contract**: `GET /api/v1/system/health`

```json
// Response
{
  "ok": true,
  "db": "healthy",
  "gmail": "healthy", 
  "queue": "healthy",
  "timestamp": "2025-08-14T10:45:00Z"
}
```

### Prometheus Metrics
**Contract**: `GET /api/v1/system/metrics`

```
# HELP phishnet_http_requests_total Total HTTP requests
# TYPE phishnet_http_requests_total counter
phishnet_http_requests_total{method="GET",status="200"} 1247
phishnet_http_requests_total{method="POST",status="200"} 89

# HELP phishnet_email_analysis_total Total emails analyzed
# TYPE phishnet_email_analysis_total counter
phishnet_email_analysis_total 892

# HELP phishnet_threat_detections_total Total threats detected
# TYPE phishnet_threat_detections_total counter
phishnet_threat_detections_total{risk="high"} 45
phishnet_threat_detections_total{risk="medium"} 123
```

## 🔌 WebSocket Events

### Connection
**Contract**: `GET /ws?token={jwt_token}`

**Connection Events**:
```json
{
  "type": "connection_established",
  "data": {
    "connection_id": "550e8400-e29b-41d4-a716-446655440000",
    "user": "admin@company.com",
    "timestamp": "2025-08-14T10:45:00Z"
  }
}
```

**Real-time Events**:

1. **Email Ingested**
```json
{
  "type": "email_ingested",
  "data": {
    "email_id": 124,
    "sender": "suspicious@domain.com",
    "subject": "Urgent: Account Verification...",
    "timestamp": "2025-08-14T10:46:00Z"
  }
}
```

2. **Analysis Complete**
```json
{
  "type": "analysis_complete",
  "data": {
    "email_id": 124,
    "risk_level": "high",
    "risk_score": 0.87,
    "confidence": 0.92,
    "processing_time_ms": 3021,
    "timestamp": "2025-08-14T10:46:03Z"
  }
}
```

3. **Action Taken**
```json
{
  "type": "action_taken",
  "data": {
    "email_id": 124,
    "action": "quarantine",
    "actor": "system",
    "timestamp": "2025-08-14T10:46:04Z"
  }
}
```

4. **Stats Updated**
```json
{
  "type": "stats_updated",
  "data": {
    "emails_today": 157,
    "threats_detected": 24,
    "emails_quarantined": 13,
    "active_users": 5,
    "timestamp": "2025-08-14T10:46:00Z"
  }
}
```

## 🛡️ Security & Error Handling

### Authentication
- **Bearer Token**: All protected endpoints require `Authorization: Bearer {access_token}`
- **Token Expiry**: Access tokens expire in 30 minutes, refresh tokens in 7 days
- **Rate Limiting**: 1000 requests per hour per user

### Standard Error Responses
```json
{
  "detail": "Error message",
  "type": "error_type",
  "code": "ERROR_CODE"
}
```

**Common HTTP Status Codes**:
- `200`: Success
- `201`: Created
- `400`: Bad Request (validation error)
- `401`: Unauthorized (invalid/expired token)
- `403`: Forbidden (insufficient permissions)
- `404`: Not Found
- `422`: Unprocessable Entity (validation error)
- `429`: Too Many Requests (rate limited)
- `500`: Internal Server Error

### Request Validation
- All request bodies are validated using Pydantic models
- Email addresses must be valid format
- URLs must be valid HTTP/HTTPS
- Dates must be ISO 8601 format
- IDs must be positive integers

## 🚀 Usage Examples

### Python Client Example
```python
import httpx
import asyncio

async def main():
    client = httpx.AsyncClient(base_url="http://localhost:8000/api/v1")
    
    # Login
    login_response = await client.post("/auth/login", json={
        "email": "admin@company.com",
        "password": "password"
    })
    
    auth_data = login_response.json()
    token = auth_data["access_token"]
    headers = {"Authorization": f"Bearer {token}"}
    
    # Get emails
    emails_response = await client.get("/emails", 
        params={"status": "quarantined", "limit": 10},
        headers=headers
    )
    
    emails = emails_response.json()
    print(f"Found {emails['total']} quarantined emails")
    
    # Analyze link
    link_response = await client.post("/links/analyze", 
        json={"url": "https://suspicious.com"},
        headers=headers
    )
    
    analysis = link_response.json()
    print(f"Risk level: {analysis['risk_level']}")

asyncio.run(main())
```

### WebSocket Client Example
```python
import websockets
import json
import asyncio

async def websocket_client():
    token = "your-jwt-token"
    uri = f"ws://localhost:8000/api/v1/ws?token={token}"
    
    async with websockets.connect(uri) as websocket:
        # Listen for events
        async for message in websocket:
            event = json.loads(message)
            print(f"Received: {event['type']}")
            
            if event['type'] == 'analysis_complete':
                data = event['data']
                print(f"Email {data['email_id']} analyzed: {data['risk_level']}")

asyncio.run(websocket_client())
```

## 📋 Testing

Run the contract tests to validate all endpoints:

```bash
# Start the PhishNet server
python run.py

# Run contract tests
python test_api_contracts.py
```

**Expected Output**:
```
🧪 PhishNet API v1 Contract Testing
==================================================
🔐 Testing Authentication API Contracts...
  • POST /api/v1/auth/login
    Status: 200
    ✅ Contract fulfilled: { access_token, refresh_token, user }
  
📧 Testing Emails API Contracts...
  • GET /api/v1/emails?status=&q=&page=&limit=
    Status: 200
    ✅ Contract fulfilled: { items:[Email], total, page, limit, has_next }

✅ API Contract Testing Complete!
```

This completes the comprehensive PhishNet API v1 contract documentation with all standardized endpoints, consistent request/response patterns, and real-world examples.
