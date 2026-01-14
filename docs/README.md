# PhishNet Documentation

Welcome to the PhishNet documentation hub. This directory contains comprehensive documentation for the PhishNet email security platform.

## 📁 Documentation Structure

### Core Documentation

| Document | Description |
|----------|-------------|
| **[QUICK_START.md](QUICK_START.md)** | Get up and running in 5 minutes |
| **[ARCHITECTURE.md](ARCHITECTURE.md)** | System architecture, components, and API reference |
| **[DEPLOYMENT.md](DEPLOYMENT.md)** | Deploy to Render/Vercel, environment variables |
| **[IMAP_EMAIL_FORWARDING.md](IMAP_EMAIL_FORWARDING.md)** | IMAP configuration, email forwarding setup |
| **[OAUTH_SETUP.md](OAUTH_SETUP.md)** | Google OAuth2 configuration |
| **[SECURITY.md](SECURITY.md)** | Security best practices and implementation |

### Legal & Compliance

| Document | Description |
|----------|-------------|
| **[PRIVACY_POLICY.md](PRIVACY_POLICY.md)** | Privacy policy |
| **[privacy-policy.html](privacy-policy.html)** | Privacy policy (HTML for web) |
| **[terms-of-service.html](terms-of-service.html)** | Terms of service (HTML for web) |

### Operational Runbooks (`runbooks/`)

Step-by-step procedures for common operational tasks:

| Runbook | Description |
|---------|-------------|
| **[deployment-procedures.md](runbooks/deployment-procedures.md)** | Deployment procedures |
| **[troubleshooting-workers.md](runbooks/troubleshooting-workers.md)** | Worker troubleshooting |
| **[standard-operating-procedures.md](runbooks/standard-operating-procedures.md)** | Standard operations |
| **[gmail-api-quota-exhaustion.md](runbooks/gmail-api-quota-exhaustion.md)** | Gmail API quota handling |
| **[sandbox-compromise.md](runbooks/sandbox-compromise.md)** | Sandbox security incidents |
| **[data-leak-response.md](runbooks/data-leak-response.md)** | Data breach response |

### Security (`security/`)

| Document | Description |
|----------|-------------|
| **[SECURITY_IMPLEMENTATION.md](security/SECURITY_IMPLEMENTATION.md)** | Security implementation details |
| **[THREAT_MODEL.md](security/THREAT_MODEL.md)** | Threat model and security analysis |

---

## 🚀 Quick Start

```bash
# Clone the repository
git clone https://github.com/your-org/phishnet.git

# Backend setup
cd backend
pip install -r requirements.txt
cp .env.example .env  # Configure your environment
uvicorn main:app --reload

# Frontend setup
cd ../frontend
npm install
npm run dev
```

**Forward emails to:** `phishnet.ai@gmail.com` to get automated phishing analysis.

---

## 🔍 Finding Information

### By Task

| Task | Documentation |
|------|---------------|
| **Initial Setup** | [QUICK_START.md](QUICK_START.md) |
| **Deploy to Production** | [DEPLOYMENT.md](DEPLOYMENT.md) |
| **Configure Email Forwarding** | [IMAP_EMAIL_FORWARDING.md](IMAP_EMAIL_FORWARDING.md) |
| **Set Up Google OAuth** | [OAUTH_SETUP.md](OAUTH_SETUP.md) |
| **Understand the System** | [ARCHITECTURE.md](ARCHITECTURE.md) |
| **Security Review** | [SECURITY.md](SECURITY.md), [security/THREAT_MODEL.md](security/THREAT_MODEL.md) |

### By Role

| Role | Start Here |
|------|------------|
| **Developers** | [ARCHITECTURE.md](ARCHITECTURE.md), [QUICK_START.md](QUICK_START.md) |
| **DevOps/SRE** | [DEPLOYMENT.md](DEPLOYMENT.md), [runbooks/](runbooks/) |
| **Security** | [SECURITY.md](SECURITY.md), [security/THREAT_MODEL.md](security/THREAT_MODEL.md) |
| **End Users** | [IMAP_EMAIL_FORWARDING.md](IMAP_EMAIL_FORWARDING.md) |

---

## 📝 Contributing to Documentation

When adding documentation:
1. Add to the appropriate consolidated document if possible
2. Update this README index
3. Use clear, concise language with examples

---

*For questions or issues, open a GitHub issue.*
