# Email Integration Testing Guide

## Overview
This document describes the comprehensive testing strategy for Gmail/Outlook email integration, including OAuth connection, real-time email retrieval, phishing analysis, and dashboard display accuracy.

## Test Objectives

### Primary Goal
**Verify that the application correctly connects to Gmail/Outlook accounts, retrieves emails in real-time, analyzes each message for phishing indicators, and displays accurate scores on the dashboard.**

## Test Suite Components

### 1. OAuth Connection Tests
**Purpose**: Verify secure authentication with email providers

#### Gmail OAuth Test (`test_gmail_oauth_connection`)
- ✅ Validates OAuth2 credentials structure
- ✅ Confirms Gmail API scopes are correct
- ✅ Verifies token exchange mechanism
- ✅ Tests credential refresh flow

**Expected Result**: Successfully authenticate with Gmail using OAuth2

#### Outlook OAuth Test (`test_outlook_connection`)
- ✅ Validates Microsoft Graph API credentials
- ✅ Confirms correct OAuth scopes
- ✅ Tests Microsoft 365 authentication

**Expected Result**: Successfully authenticate with Outlook/Microsoft 365

---

### 2. Email Retrieval Tests
**Purpose**: Confirm real-time email fetching from inbox

#### Real-time Retrieval Test (`test_email_retrieval_realtime`)
- ✅ Fetches emails from Gmail inbox
- ✅ Retrieves email metadata (sender, subject, date)
- ✅ Extracts email body content
- ✅ Handles pagination for large inboxes

**Test Data**: 3 sample emails with varying risk levels

**Expected Result**: Successfully retrieve all emails with complete metadata

---

### 3. Phishing Analysis Tests
**Purpose**: Validate accurate phishing detection per email

#### Per-Email Analysis Test (`test_phishing_analysis_per_email`)
Analyzes each email for:
- 🔍 **Suspicious URLs**: Detects phishing links
- 🔍 **Sender Spoofing**: Identifies fake sender addresses
- 🔍 **Urgency Keywords**: Flags urgent/threatening language
- 🔍 **Malicious Attachments**: Detects dangerous file types
- 🔍 **Domain Reputation**: Checks sender domain trust

**Test Scenarios**:

1. **High-Risk Email** (msg_001)
   - From: `noreply@paypal-secure.com` (spoofed)
   - Subject: "URGENT: Verify your account now!"
   - Contains: Suspicious URL `http://paypal-login.phishing.com`
   - **Expected Score**: 0.85 (High Risk)
   - **Expected Indicators**: suspicious_url, urgency_keywords, spoofed_sender

2. **Low-Risk Email** (msg_002)
   - From: `security@microsoft.com` (legitimate)
   - Subject: "Microsoft Account Activity"
   - Contains: Standard security notification
   - **Expected Score**: 0.15 (Low Risk)
   - **Expected Indicators**: None

3. **Critical-Risk Email** (msg_003)
   - From: `admin@company-secure.xyz` (suspicious domain)
   - Subject: "Re: Quarterly Report - Immediate Action Required"
   - Contains: Malicious attachment link `.exe` file
   - **Expected Score**: 0.95 (Critical Risk)
   - **Expected Indicators**: malicious_attachment, urgency, suspicious_domain

**Expected Result**: Each email receives appropriate risk score and indicators

---

### 4. Dashboard Display Tests
**Purpose**: Verify accurate score display on dashboard

#### Dashboard Accuracy Test (`test_dashboard_display_accuracy`)
Validates:
- ✅ All analyzed emails appear on dashboard
- ✅ Phishing scores are correctly displayed
- ✅ Risk levels are accurately shown (Critical/High/Medium/Low)
- ✅ Status badges reflect analysis state
- ✅ Email metadata is complete (sender, subject, date)

**Dashboard Elements Checked**:
```json
{
  "id": "msg_001",
  "subject": "URGENT: Verify your account now!",
  "sender": "noreply@paypal-secure.com",
  "phishing_score": 0.85,
  "risk_level": "high",
  "status": "analyzed",
  "indicators_count": 3
}
```

**Expected Result**: Dashboard displays all emails with accurate risk scores and visual indicators

---

### 5. Real-time Update Tests
**Purpose**: Verify automatic detection of new emails

#### Real-time Monitoring Test (`test_realtime_updates`)
- ✅ Detects new incoming emails automatically
- ✅ Analyzes new emails without manual refresh
- ✅ Updates dashboard in real-time
- ✅ Maintains analysis history

**Test Flow**:
1. Load initial emails (2 messages)
2. Simulate new email arrival (1 message)
3. Verify automatic detection
4. Confirm automatic analysis
5. Validate dashboard update

**Expected Result**: New emails are automatically detected, analyzed, and displayed

---

### 6. End-to-End Integration Tests
**Purpose**: Complete workflow validation

#### Full Integration Test (`test_end_to_end_flow`)
**Complete Flow**:
1. **Connect** → Authenticate with Gmail/Outlook
2. **Retrieve** → Fetch emails from inbox
3. **Analyze** → Scan each email for phishing
4. **Display** → Show results on dashboard

**Verification Points**:
- ✅ Connection status: "connected"
- ✅ Email retrieval: All emails fetched
- ✅ Analysis complete: Every email scanned
- ✅ Dashboard updated: All results displayed

**Expected Result**: Seamless end-to-end operation from connection to display

---

## Test Execution

### Quick Test (Smoke Test)
```bash
cd backend
python testsprite_tests/run_email_tests.py --quick
```

### Full Test Suite
```bash
cd backend
python testsprite_tests/run_email_tests.py
```

### Individual Test
```bash
cd backend
pytest tests/integration/test_email_integration_full.py -k test_gmail_oauth_connection -v
```

---

## Test Results Format

### Success Criteria
- ✅ **OAuth Connection**: Successfully authenticate
- ✅ **Email Retrieval**: Fetch all emails with metadata
- ✅ **Phishing Analysis**: Accurate risk scores (±0.05)
- ✅ **Dashboard Display**: 100% email visibility
- ✅ **Real-time Updates**: <5 second detection latency
- ✅ **End-to-End Flow**: Complete without errors

### Sample Test Output
```
=== Test 3: Email Phishing Analysis ===

✓ Email msg_001 analyzed:
  - Subject: URGENT: Verify your account now!
  - Risk Level: high
  - Phishing Score: 0.85
  - Indicators: suspicious_url, urgency_keywords, spoofed_sender

✓ Email msg_002 analyzed:
  - Subject: Microsoft Account Activity
  - Risk Level: low
  - Phishing Score: 0.15
  - Indicators: None

✓ Email msg_003 analyzed:
  - Subject: Re: Quarterly Report - Immediate Action Required
  - Risk Level: critical
  - Phishing Score: 0.95
  - Indicators: malicious_attachment, urgency, suspicious_domain
```

---

## Dashboard Verification Checklist

When testing dashboard display:

### Email Card Display
- [ ] Email ID visible
- [ ] Subject line displayed
- [ ] Sender address shown
- [ ] Received date/time present
- [ ] Phishing score displayed (0.00-1.00)
- [ ] Risk badge color-coded:
  - 🔴 Critical (0.80-1.00)
  - 🟠 High (0.60-0.79)
  - 🟡 Medium (0.40-0.59)
  - 🟢 Low (0.00-0.39)

### Dashboard Statistics
- [ ] Total emails count correct
- [ ] High-risk count accurate
- [ ] Medium-risk count accurate
- [ ] Low-risk count accurate
- [ ] Risk distribution chart displays correctly

### Real-time Features
- [ ] WebSocket connection active
- [ ] New email notifications appear
- [ ] Dashboard auto-refreshes
- [ ] Analysis status updates live

---

## Known Test Scenarios

### Test Email 1: PayPal Phishing Attempt
```
From: noreply@paypal-secure.com (SPOOFED)
Subject: URGENT: Verify your account now!
Body: Your account will be suspended. Click here: http://paypal-login.phishing.com
Risk: HIGH (0.85)
Indicators: 3 detected
```

### Test Email 2: Legitimate Microsoft Notification
```
From: security@microsoft.com (LEGITIMATE)
Subject: Microsoft Account Activity
Body: Thank you for using Microsoft services. Your account is secure.
Risk: LOW (0.15)
Indicators: 0 detected
```

### Test Email 3: Malicious Attachment
```
From: admin@company-secure.xyz (SUSPICIOUS)
Subject: Re: Quarterly Report - Immediate Action Required
Body: Urgent! Download attachment: document.exe
Risk: CRITICAL (0.95)
Indicators: 3 detected (malicious file type)
```

---

## Troubleshooting

### Common Issues

#### Test Fails: OAuth Connection
**Solution**: Check credentials in `.env` file
```bash
GOOGLE_CLIENT_ID=your_client_id
GOOGLE_CLIENT_SECRET=your_client_secret
MICROSOFT_CLIENT_ID=your_client_id
MICROSOFT_CLIENT_SECRET=your_client_secret
```

#### Test Fails: Email Retrieval
**Solution**: Verify Gmail API is enabled in Google Cloud Console

#### Test Fails: Dashboard Display
**Solution**: Check frontend is running on correct port (3000)

#### Test Timeout
**Solution**: Increase timeout in test configuration or check network connectivity

---

## Continuous Integration

### GitHub Actions Workflow
```yaml
name: Email Integration Tests
on: [push, pull_request]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Run TestSprite
        run: |
          cd backend
          python testsprite_tests/run_email_tests.py
```

---

## Test Maintenance

### When to Update Tests
- ✅ New email provider added (e.g., Yahoo, ProtonMail)
- ✅ Phishing detection algorithm changes
- ✅ Dashboard UI updates
- ✅ OAuth flow modifications
- ✅ New risk scoring criteria

### Test Data Management
- Keep sample emails in `fixtures/sample_emails.json`
- Update expected scores when algorithm improves
- Add new test scenarios for edge cases

---

## Success Metrics

### Target Metrics
- **Test Coverage**: >90%
- **Pass Rate**: >95%
- **Execution Time**: <2 minutes (full suite)
- **False Positive Rate**: <5%
- **Detection Accuracy**: >95%

---

## Contact

For questions about testing:
- Review test code: `backend/tests/integration/test_email_integration_full.py`
- Check test runner: `backend/testsprite_tests/run_email_tests.py`
- See test results: `backend/testsprite_tests/tmp/test_results_*.json`

---

**Last Updated**: October 13, 2025
**Test Suite Version**: 1.0.0
**Status**: Production Ready ✅
