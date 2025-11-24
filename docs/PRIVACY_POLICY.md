# PhishNet Privacy Policy

**Effective Date**: November 3, 2025  
**Last Updated**: November 3, 2025

## Overview

PhishNet ("we", "our", or "us") provides email security analysis services. We are committed to protecting your privacy and giving you control over your data. This policy explains how we collect, use, and protect your information when you use our service.

---

## Two Operating Modes

PhishNet offers two distinct modes of operation, each with different privacy implications:

### Mode 1: Bulk Forward Mode (IMAP-based)

**What it does**: You forward all your emails to a PhishNet inbox for automatic analysis.

**Data collection**:
- ✅ Full email content (headers, body, attachments)
- ✅ Sender and recipient information
- ✅ Email metadata (date, time, size)
- ✅ Analysis results and threat scores

**Data storage**:
- Stored in our secure database
- Retained for 90 days by default (configurable)
- Encrypted at rest

**Your control**:
- You can delete specific emails
- You can delete all your data
- You can stop forwarding anytime

**Use case**: Best for users who want comprehensive, automated protection.

---

### Mode 2: On-Demand Check Mode (Gmail API)

**What it does**: You check individual suspicious emails by clicking a button.

**Data collection (without consent)**:
- ❌ We DO NOT store the email content
- ❌ We DO NOT store sender/subject information
- ✅ We log metadata only (timestamp, action, result)

**Data collection (with your consent)**:
- ✅ Email metadata (sender, subject, date)
- ✅ Analysis results and threat scores
- ✅ Raw email content (optional)
- ✅ Retained for 30 days, then auto-deleted

**Your control**:
- You choose which emails to check
- You choose whether to save results
- You can delete saved data anytime
- You can export all data anytime
- You can revoke Gmail access anytime

**Use case**: Best for privacy-conscious users who only need occasional checks.

---

## Information We Collect

### Account Information
- Email address
- Username
- Authentication tokens (encrypted)

### Email Data (Mode 1 only, or Mode 2 with consent)
- Email content, headers, and attachments
- Sender and recipient information
- Timestamps and metadata

### Technical Information
- IP address (for security)
- Browser/device information
- Access logs

### Analysis Results
- Threat scores and risk levels
- Detected indicators (suspicious links, patterns)
- Recommendations

---

## How We Use Your Information

### Email Analysis
- Detect phishing attempts
- Identify malicious links and attachments
- Provide threat intelligence
- Improve detection accuracy

### Service Operation
- Authenticate users
- Prevent abuse
- Improve service quality
- Comply with legal obligations

### What We DON'T Do
- ❌ We DO NOT sell your data
- ❌ We DO NOT share data with third parties (except as required by law)
- ❌ We DO NOT use your data for advertising
- ❌ We DO NOT read your emails for purposes other than security analysis

---

## Data Storage and Security

### Encryption
- **At rest**: AES-256 encryption
- **In transit**: TLS 1.3 (HTTPS)
- **OAuth tokens**: Encrypted with Fernet

### Access Controls
- Role-based access control
- Audit logging of all access
- Multi-factor authentication (for admins)

### Data Retention

**Mode 1 (Bulk Forward)**:
- Email content: 90 days (default, configurable)
- Analysis results: 90 days
- Audit logs: 1 year

**Mode 2 (On-Demand)**:
- Without consent: Immediate deletion after analysis
- With consent: 30 days, then auto-deletion
- Audit logs: 1 year

---

## Your Rights

### Access
- View all data we have about you
- Download your data (JSON format)

### Deletion
- Delete specific emails or analyses
- Delete all your data
- Request account deletion

### Portability
- Export all your data
- Machine-readable format (JSON)

### Revocation
- Revoke OAuth access anytime
- Stop email forwarding anytime

---

## Third-Party Services

We use the following third-party services:

### Google Gmail API (Mode 2 only)
- **Purpose**: Fetch individual emails for on-demand checking
- **Data shared**: Message ID only (not email content)
- **Privacy**: We request minimal scope (gmail.readonly)
- **Control**: You can revoke access anytime in your Google account settings

### VirusTotal (Optional)
- **Purpose**: Check links and attachments against threat database
- **Data shared**: URLs and file hashes only (no email content)
- **Privacy**: Anonymized queries

### AbuseIPDB (Optional)
- **Purpose**: Check IP address reputation
- **Data shared**: IP addresses from email headers only
- **Privacy**: Anonymized queries

---

## Cookies and Tracking

We use minimal cookies:

### Essential Cookies
- Session authentication (JWT)
- CSRF protection

### Analytics (Optional)
- Anonymous usage statistics
- No personally identifiable information
- You can opt out

We DO NOT use:
- ❌ Advertising cookies
- ❌ Cross-site tracking
- ❌ Third-party analytics (Google Analytics, etc.)

---

## Children's Privacy

PhishNet is not intended for users under 13 years of age. We do not knowingly collect information from children.

---

## International Data Transfers

Your data may be stored in:
- United States (MongoDB Atlas)
- European Union (if configured)

We ensure adequate protection through:
- Standard contractual clauses
- Encryption in transit and at rest
- GDPR compliance

---

## Changes to This Policy

We may update this policy from time to time. We will:
- Notify you by email of significant changes
- Post the updated policy on our website
- Update the "Last Updated" date

---

## Compliance

We comply with:
- GDPR (European Union)
- CCPA (California)
- Google OAuth verification requirements
- Industry best practices

---

## Contact Us

For privacy questions or data requests:

- **Email**: privacy@phishnet.com
- **Data Protection Officer**: dpo@phishnet.com
- **Security Issues**: security@phishnet.com

---

## Data Breach Notification

In the unlikely event of a data breach:
- We will notify affected users within 72 hours
- We will describe the breach and our response
- We will provide guidance on protective measures

---

## Your California Privacy Rights (CCPA)

California residents have the right to:
- Know what personal information we collect
- Request deletion of personal information
- Opt out of sale (we don't sell data)
- Non-discrimination for exercising rights

---

## GDPR Rights (EU Users)

Under GDPR, you have the right to:
- Access your personal data
- Rectify inaccurate data
- Erase your data ("right to be forgotten")
- Restrict processing
- Data portability
- Object to processing
- Withdraw consent

To exercise these rights, contact privacy@phishnet.com

---

## Automated Decision Making

We use automated analysis to:
- Calculate threat scores
- Detect phishing patterns
- Recommend actions

You have the right to:
- Request human review
- Challenge automated decisions
- Provide additional context

---

## Data Protection by Design

PhishNet is built with privacy in mind:

### Mode 2 Design Principles
1. **Data Minimization**: Only fetch what's needed
2. **Purpose Limitation**: Use data only for security analysis
3. **Storage Limitation**: Auto-delete after retention period
4. **Transparency**: Clear consent and audit trails
5. **User Control**: Delete and export anytime

---

## Questions?

If you have questions about this privacy policy, please contact us at privacy@phishnet.com

---

**© 2025 PhishNet. All rights reserved.**

This privacy policy was last updated on November 3, 2025, and is effective as of that date.
