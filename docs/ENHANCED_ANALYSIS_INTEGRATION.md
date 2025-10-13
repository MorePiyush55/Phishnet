# Enhanced Phishing Analysis Integration

## Overview

This document describes the integration of advanced phishing detection features from ThePhish and email-phishing-detection-add-in projects into PhishNet.

## New Features

### 1. Sender Analysis (15% weight)
**Purpose:** Detect sender spoofing and display name impersonation

**Checks:**
- Display name vs email address similarity scoring
- Sender IP address extraction
- Suspicious display name patterns (e.g., "PayPal Support", "Bank Security")
- Free email domain detection (Gmail, Yahoo, etc.)

**Scoring:**
- 100%: Perfect match between display name and email
- 75-99%: Most parts of name found in email
- 50-74%: Parts of name found in email
- 0-49%: Low/no similarity (HIGH RISK)

**Example:**
```
Display Name: "Amazon Security Team"
Email: random123@gmail.com
Similarity: 5% → SUSPICIOUS (likely impersonation)
```

### 2. Content Analysis (20% weight)
**Purpose:** Detect phishing language patterns and urgency tactics

**Checks:**
- 50+ phishing keyword detection (urgent, verify, suspended, etc.)
- Urgency level assessment (LOW/MEDIUM/HIGH)
- Threatening language patterns
- Financial/banking keyword presence

**Scoring:**
- 100%: No phishing keywords detected
- 50-99%: 1-5 keywords detected
- 0-49%: 5+ keywords detected (HIGH RISK)

**Phishing Keyword Categories:**
1. **Urgency:** urgent, immediate, action required, expires
2. **Financial:** account, bank, credit card, payment, wire transfer
3. **Threats:** suspended, locked, blocked, compromised, breach
4. **Actions:** click here, download, reset password, verify
5. **Rewards:** winner, prize, free, claim, bonus

### 3. Link Analysis (20% weight)
**Purpose:** Detect malicious links and suspicious URL patterns

**Checks:**
- HTTP vs HTTPS protocol analysis
- URL encoding detection (obfuscation)
- Redirection detection (redirect, /r/, r?)
- Link duplication counting
- Suspicious TLD detection (.tk, .ml, .ga, .xyz, etc.)

**Scoring:**
- **HTTPS Score:** (HTTPS links / Total links) × 100
- **Encoding Score:** ((Total - Encoded) / Total) × 100
- **Redirect Score:** ((Total - Redirects) / Total) × 100
- **Duplication Score:** ((Total - Duplicates) / Total) × 100
- **Overall:** Average of all sub-scores

**Example:**
```
Total Links: 5
HTTPS: 2, HTTP: 3 → HTTPS Score: 40% (HIGH RISK)
Encoded: 2 → Encoding Score: 60%
Redirects: 1 → Redirect Score: 80%
Overall Link Score: 60% (SUSPICIOUS)
```

### 4. Authentication Analysis (30% weight - highest priority)
**Purpose:** Verify email authenticity through email authentication protocols

**Checks:**
- **SPF (Sender Policy Framework):** Verifies sending server authorization
- **DKIM (DomainKeys Identified Mail):** Verifies message integrity and sender
- **DMARC (Domain-based Message Authentication):** Policy enforcement

**Scoring:**
- **SPF Results:**
  - `pass`: 100% → Authorized sender
  - `fail`: 0% → Unauthorized sender (CRITICAL)
  - `softfail`: 0% → Likely unauthorized
  - `neutral`: 0% → No validation
  - `none`: 0% → No SPF record (HIGH RISK)

- **DKIM Results:**
  - `pass`: 100% → Signature verified
  - `fail`: 0% → Signature verification failed (CRITICAL)
  - `none`: 0% → No DKIM signature

- **DMARC Results:**
  - `pass`: 100% → Authenticated
  - `fail`: 0% → Authentication failed (CRITICAL)
  - `bestguesspass`: 50% → Partial authentication
  - `none`: 0% → No DMARC policy

**Overall Authentication Score:** Average of SPF + DKIM + DMARC

**Example:**
```
SPF: pass (100%)
DKIM: fail (0%)
DMARC: fail (0%)
Overall Authentication: 33% → PHISHING (likely spoofed email)
```

### 5. Attachment Analysis (15% weight)
**Purpose:** Detect dangerous file types and suspicious attachments

**Checks:**
- Total attachment count
- File extension analysis
- Dangerous extension detection (42 types)
- SHA256 hash calculation for each attachment

**Dangerous Extensions:**
- **Executables:** .exe, .bat, .cmd, .com, .scr, .msi
- **Scripts:** .vbs, .js, .ps1, .sh, .py, .pl
- **Archives:** .zip, .rar, .7z, .iso
- **Office Macros:** .docm, .xlsm, .pptm

**Scoring:**
- 100%: No attachments
- 70-99%: 1-2 safe attachments
- 50-69%: 3+ attachments
- 0-49%: Dangerous file type detected (CRITICAL)

## Total Scoring System

### Weighted Average Calculation
```
Total Score = (
    Sender Score × 0.15 +
    Content Score × 0.20 +
    Link Score × 0.20 +
    Authentication Score × 0.30 +
    Attachment Score × 0.15
)
```

### Final Verdict Decision
- **SAFE (70-100%):** Email appears legitimate
  - All authentication checks pass
  - No critical red flags
  - Confidence: 70-95%

- **SUSPICIOUS (40-69%):** Email requires caution
  - 1 critical red flag OR moderate score
  - Some authentication failures
  - Confidence: 50-70%

- **PHISHING (0-39%):** Email is highly likely malicious
  - 2+ critical red flags OR very low score
  - Multiple authentication failures
  - Dangerous attachments present
  - Confidence: 90%+

### Critical Red Flags
Any 2 of the following trigger PHISHING verdict:
1. Dangerous file extension in attachment
2. SPF authentication failure
3. DKIM authentication failure
4. All links are HTTP (no HTTPS)

## Integration Architecture

### Backend Service Flow
```
EmailMessage → EnhancedPhishingAnalyzer → ComprehensivePhishingAnalysis
                        ↓
    ┌───────────────────┼───────────────────┐
    ↓                   ↓                   ↓
SenderAnalysis   ContentAnalysis    LinkAnalysis
    ↓                   ↓                   ↓
AuthenticationAnalysis  AttachmentAnalysis
    ↓                   ↓
    └───────────────────┴──────────────────→
              Total Score + Verdict
```

### Database Schema Updates
Add new fields to `email_analyses` table:
```python
{
    # Existing fields
    "email_id": str,
    "risk_score": float,
    
    # New section scores
    "sender_score": int,  # 0-100
    "content_score": int,  # 0-100
    "link_score": int,  # 0-100
    "authentication_score": int,  # 0-100
    "attachment_score": int,  # 0-100
    
    # Authentication details
    "spf_result": str,  # pass/fail/none
    "dkim_result": str,
    "dmarc_result": str,
    
    # Risk indicators
    "risk_factors": List[str],
    "phishing_keywords": List[str],
    "suspicious_links": List[Dict],
    "dangerous_attachments": List[str]
}
```

### API Response Format
```json
{
    "email_id": "msg_12345",
    "total_score": 45,
    "verdict": "SUSPICIOUS",
    "confidence": 0.65,
    "risk_factors": [
        "SPF check failed",
        "Low similarity between display name and email",
        "Multiple phishing keywords detected (7)"
    ],
    "sections": {
        "sender": {
            "score": 30,
            "display_name": "PayPal Security",
            "email_address": "random@gmail.com",
            "similarity": 0.15,
            "indicators": ["Low similarity", "Free email domain"]
        },
        "content": {
            "score": 40,
            "keyword_count": 7,
            "urgency_level": "HIGH",
            "indicators": ["Multiple phishing keywords (7)", "Urgency level: HIGH"]
        },
        "links": {
            "score": 60,
            "total_links": 5,
            "https_links": 2,
            "http_links": 3,
            "indicators": ["3 HTTP (non-secure) links found"]
        },
        "authentication": {
            "score": 33,
            "spf_result": "fail",
            "dkim_result": "fail",
            "dmarc_result": "none",
            "indicators": ["SPF check failed", "DKIM check failed"]
        },
        "attachments": {
            "score": 50,
            "total_attachments": 1,
            "dangerous_extensions": ["invoice.exe"],
            "indicators": ["Dangerous file types: invoice.exe"]
        }
    }
}
```

## Frontend Dashboard Updates

### Section Score Display
Each section displays:
1. **Percentage Score (0-100%)**
2. **Color-coded Bar:**
   - Green (80-100%): Safe
   - Yellow (50-79%): Caution
   - Red (0-49%): Danger
3. **Specific Indicators List**

### Visual Layout
```
┌─────────────────────────────────────────────┐
│ Email: invoice@company.com                  │
│ Total Score: 45% (SUSPICIOUS)               │
│ ████████████████░░░░░░░░░░░░░░░░░░░░ 45%   │
└─────────────────────────────────────────────┘

┌──────────────┬──────────────┬──────────────┐
│ 🧑 Sender    │ 📝 Content   │ 🔗 Links     │
│ 30%          │ 40%          │ 60%          │
│ ██████░░░░░░ │ ████████░░░░ │ ████████████ │
│ ⚠️ Low       │ ⚠️ 7 keywords│ ⚠️ 3 HTTP    │
│ similarity   │ detected     │ links        │
└──────────────┴──────────────┴──────────────┘

┌──────────────┬──────────────────────────────┐
│ 🔐 Auth      │ 📎 Attachments               │
│ 33%          │ 50%                          │
│ ██████░░░░░░ │ ██████████░░░░░░░░░░░░░░     │
│ ❌ SPF fail  │ ⚠️ Dangerous file: invoice.exe│
│ ❌ DKIM fail │                               │
└──────────────┴──────────────────────────────┘
```

## Implementation Steps

### Phase 1: Backend Service (Completed)
✅ Created `EnhancedPhishingAnalyzer` class
✅ Implemented 5 analysis modules:
   - Sender analysis with similarity scoring
   - Content analysis with phishing keywords
   - Link analysis with protocol/encoding checks
   - Authentication analysis (SPF/DKIM/DMARC)
   - Attachment analysis with dangerous file detection
✅ Weighted scoring system (30% auth, 20% content, 20% links, 15% sender, 15% attachments)
✅ Final verdict determination with confidence levels

### Phase 2: Integration with Orchestrator (Next)
- [ ] Import `EnhancedPhishingAnalyzer` in `enhanced_threat_orchestrator.py`
- [ ] Call analyzer before or alongside existing ML models
- [ ] Merge enhanced analysis results with existing threat data
- [ ] Store section scores in database

### Phase 3: API Endpoint Updates
- [ ] Update `POST /api/analyze` to include section scores
- [ ] Add `GET /api/analysis/{email_id}/sections` endpoint
- [ ] Include authentication results in response

### Phase 4: Frontend Dashboard
- [ ] Create `SectionScoreCard` React component
- [ ] Add color-coded progress bars
- [ ] Display risk factors and indicators
- [ ] Add expandable details for each section

### Phase 5: Testing
- [ ] Unit tests for each analysis module
- [ ] Integration tests with sample phishing emails
- [ ] Validation with test suite (high/low/critical risk emails)

## Usage Example

```python
from backend.app.services.enhanced_phishing_analyzer import EnhancedPhishingAnalyzer

# Initialize analyzer
analyzer = EnhancedPhishingAnalyzer()

# Analyze email
with open('email.eml', 'rb') as f:
    email_content = f.read()

result = analyzer.analyze_email(email_content)

# Access results
print(f"Total Score: {result.total_score}%")
print(f"Verdict: {result.final_verdict}")
print(f"Confidence: {result.confidence}")

print(f"\nSender Analysis:")
print(f"  Score: {result.sender.score}%")
print(f"  Similarity: {result.sender.name_email_similarity:.2f}")
print(f"  Indicators: {result.sender.indicators}")

print(f"\nAuthentication:")
print(f"  SPF: {result.authentication.spf_result} ({result.authentication.spf_score}%)")
print(f"  DKIM: {result.authentication.dkim_result} ({result.authentication.dkim_score}%)")
print(f"  DMARC: {result.authentication.dmarc_result} ({result.authentication.dmarc_score}%)")

print(f"\nRisk Factors:")
for factor in result.risk_factors:
    print(f"  - {factor}")
```

## Testing Strategy

### Test Email Samples
1. **Legitimate Email:**
   - SPF/DKIM/DMARC: All pass
   - Sender similarity: High
   - No phishing keywords
   - HTTPS links only
   - Expected Score: 85-95%

2. **Phishing Email:**
   - SPF/DKIM/DMARC: All fail
   - Sender similarity: Low (<30%)
   - 5+ phishing keywords
   - HTTP links + encoding
   - Dangerous attachment (.exe)
   - Expected Score: 0-30%

3. **Suspicious Email:**
   - SPF: pass, DKIM/DMARC: fail
   - Sender similarity: Medium
   - 2-3 phishing keywords
   - Mixed HTTP/HTTPS links
   - Expected Score: 40-60%

## Performance Considerations

- **Average Analysis Time:** <100ms per email
- **Memory Usage:** ~5MB per email analysis
- **Scalability:** Stateless design, horizontally scalable
- **Caching:** Authentication results can be cached per domain

## Security Considerations

- Email content is processed in-memory only (not stored)
- Attachment hashes calculated without executing files
- No external API calls (fully offline analysis)
- Regular updates to phishing keyword database

## Maintenance

### Regular Updates Required
1. **Phishing Keyword List:** Quarterly updates
2. **Dangerous Extensions:** As new threats emerge
3. **Suspicious TLDs:** Monthly review
4. **Free Email Domains:** Annual update

## References

- **ThePhish:** https://github.com/emalderson/ThePhish
- **email-phishing-detection-add-in:** https://github.com/NETponents/email-phishing-detection-add-in
- **SPF RFC:** RFC 7208
- **DKIM RFC:** RFC 6376
- **DMARC RFC:** RFC 7489
