# PhishNet Security Guide

## Overview

PhishNet implements multiple security layers to protect user data and ensure secure email analysis.

---

## Authentication

### JWT Tokens
- **Access Token**: 30 minutes expiry
- **Refresh Token**: 7 days expiry, rotated on use
- **Algorithm**: HS256
- **Minimum Secret Key**: 32 characters

### Password Security
- **Hashing**: bcrypt with 12 rounds
- **Minimum Length**: 8 characters
- **Requirements**: Special characters enforced

### OAuth 2.0
- Google OAuth for Gmail integration
- PKCE flow for enhanced security
- Scope limitations (minimum required)

---

## API Security

### Rate Limiting
| Endpoint | Limit |
|----------|-------|
| Login | 5/minute |
| API | 100/minute |
| Analysis | 50/minute |

### Input Validation
- Pydantic models for request validation
- Email content size limit: 1MB
- Maximum URLs per email: 10
- Analysis timeout: 5 minutes

### CORS Configuration
```python
CORS_ORIGINS = [
    "https://phishnet-tau.vercel.app",
    "http://localhost:3000",
    "http://localhost:5173"
]
```

---

## Data Protection

### Data Storage
- MongoDB Atlas with encryption at rest
- TLS 1.2+ for data in transit
- Database access limited to application IP

### Email Data Handling
- Full email content NOT stored permanently
- Only metadata and analysis results retained
- Message-ID used for deduplication

### Retention Policy
- Analysis results: 90 days default
- User can request data deletion
- Logs rotated daily

---

## Secret Management

### Environment Variables
All sensitive data stored as environment variables:
```env
SECRET_KEY=...          # JWT signing key
MONGODB_URI=...         # Database connection
IMAP_PASSWORD=...       # Email access
GMAIL_CLIENT_SECRET=... # OAuth secret
VIRUSTOTAL_API_KEY=...  # Threat intel
```

### Best Practices
- Never expose client secrets in frontend
- Use HTTPS for all production endpoints
- Store secrets in Render/Vercel environment variables
- Use server-side token exchange
- Rotate secrets regularly

---

## Threat Mitigations

| Vector | Mitigation |
|--------|------------|
| Email injection | Content sanitization, no raw HTML in responses |
| Prompt injection | Gemini receives structured data only, not raw email |
| CSRF | State parameter in OAuth, SameSite cookies |
| XSS | React escaping, CSP headers |
| SQL/NoSQL injection | Parameterized queries, Pydantic validation |
| Credential stuffing | Rate limiting, account lockout |

---

## Recommended Headers

```
Content-Security-Policy: default-src 'self'
X-Frame-Options: DENY
X-Content-Type-Options: nosniff
Strict-Transport-Security: max-age=31536000
```

---

## Incident Response

1. Check Render logs for unusual patterns
2. Rotate compromised credentials immediately
3. Review MongoDB access logs
4. Notify affected users if data breach
5. Report to authorities if required (GDPR: 72 hours)

