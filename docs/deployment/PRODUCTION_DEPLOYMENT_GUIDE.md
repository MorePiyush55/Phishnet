# PhishNet Enhanced v2.0 - Production Deployment Guide

## Architecture Overview

PhishNet Enhanced is a production-ready, privacy-first email threat analysis system with:

### Core Components
- **FastAPI Backend**: Async API with comprehensive security middleware
- **PostgreSQL 15**: Primary database with privacy-compliant data models
- **Redis 7**: Task queues, caching, and session management
- **Docker Compose**: Multi-service architecture with workers and API
- **Gmail OAuth 2.0**: Secure integration with encrypted credential storage
- **Google Cloud Pub/Sub**: Real-time email notification system
- **WebSocket Manager**: Real-time dashboard updates
- **Multi-Worker Architecture**: Scalable email and threat processing

### Security Features
- Encrypted credential storage using Fernet encryption
- CSRF protection for OAuth flows
- Rate limiting and request validation
- Comprehensive audit logging
- Security headers middleware
- TLS/HTTPS enforcement

### Privacy & Compliance
- GDPR-compliant data models and operations
- Consent management system
- Right to Erasure (data deletion)
- Right to Data Portability (data export)
- Automated data retention policies
- Privacy-by-design architecture

## Prerequisites

### System Requirements
- Docker & Docker Compose
- 4GB+ RAM
- 10GB+ storage
- SSL certificates (for production)

### External Services
- Google Cloud Project with Gmail API enabled
- Google Cloud Pub/Sub topic and subscription
- VirusTotal API key (optional)
- AbuseIPDB API key (optional)
- Google Gemini API key (optional)

## Quick Start

### 1. Environment Setup

```bash
# Clone the repository
git clone <repository-url>
cd phishnet-enhanced

# Copy environment template
cp env.example .env

# Edit environment variables
nano .env
```

### 2. Configure Environment Variables

```bash
# Core Settings
DATABASE_URL=postgresql://phishnet:secure_password@postgres:5432/phishnet
REDIS_URL=redis://redis:6379/0
SECRET_KEY=your-super-secure-secret-key-here

# Security
ENCRYPTION_KEY=your-32-byte-base64-encoded-encryption-key
DOMAIN_NAME=yourdomain.com
BASE_URL=https://yourdomain.com

# Gmail OAuth
GOOGLE_CLIENT_ID=your-client-id.apps.googleusercontent.com
GOOGLE_CLIENT_SECRET=your-client-secret
GOOGLE_REDIRECT_URI=https://yourdomain.com/api/v1/auth/gmail/callback

# Google Cloud Pub/Sub
GOOGLE_CLOUD_PROJECT_ID=your-project-id
PUBSUB_TOPIC=gmail-notifications
PUBSUB_SUBSCRIPTION=gmail-notifications-sub
GOOGLE_APPLICATION_CREDENTIALS=/app/credentials/service-account.json

# External APIs (Optional)
VIRUSTOTAL_API_KEY=your-virustotal-api-key
ABUSEIPDB_API_KEY=your-abuseipdb-api-key
GEMINI_API_KEY=your-gemini-api-key

# Worker Configuration
EMAIL_WORKER_COUNT=3
THREAT_WORKER_COUNT=2
WEBHOOK_WORKER_COUNT=2

# Features
DEBUG=false
SERVE_STATIC=true
LOG_LEVEL=INFO
```

### 3. Production Deployment

```bash
# Start production services
docker-compose -f docker-compose.prod.yml up -d

# Check service status
docker-compose -f docker-compose.prod.yml ps

# View logs
docker-compose -f docker-compose.prod.yml logs -f api
```

## Service Architecture

### API Service (`phishnet-api`)
- **Port**: 8000 (internal), 443 (external via reverse proxy)
- **Purpose**: Main FastAPI application with all endpoints
- **Scaling**: Horizontal (add more replicas)
- **Health Check**: `/health`

### Webhook Service (`phishnet-webhook`)
- **Port**: 8001 (internal)
- **Purpose**: Handles Gmail Pub/Sub notifications
- **Scaling**: Horizontal based on webhook volume
- **Health Check**: `/webhook/health`

### Email Workers (`phishnet-email-worker`)
- **Purpose**: Process Gmail emails from queue
- **Scaling**: Configured by `EMAIL_WORKER_COUNT`
- **Queue**: `email_processing_queue`

### Threat Workers (`phishnet-threat-worker`)
- **Purpose**: Analyze emails for threats
- **Scaling**: Configured by `THREAT_WORKER_COUNT`  
- **Queue**: `threat_analysis_queue`

### Database (`postgres`)
- **Version**: PostgreSQL 15
- **Purpose**: Primary data storage
- **Backup**: Automated daily backups recommended

### Cache/Queue (`redis`)
- **Version**: Redis 7
- **Purpose**: Queues, sessions, caching
- **Persistence**: RDB snapshots enabled

## Google Cloud Setup

### 1. Create Google Cloud Project
```bash
# Install gcloud CLI
# Create project
gcloud projects create phishnet-prod --name="PhishNet Production"

# Enable APIs
gcloud services enable gmail.googleapis.com pubsub.googleapis.com
```

### 2. Setup OAuth Credentials
```bash
# Go to Google Cloud Console > Credentials
# Create OAuth 2.0 Client ID
# Add authorized redirect URIs:
# - https://yourdomain.com/api/v1/auth/gmail/callback
```

### 3. Setup Pub/Sub
```bash
# Create topic and subscription
gcloud pubsub topics create gmail-notifications
gcloud pubsub subscriptions create gmail-notifications-sub --topic=gmail-notifications

# Create service account
gcloud iam service-accounts create phishnet-service \
    --description="PhishNet service account" \
    --display-name="PhishNet Service"

# Grant permissions
gcloud projects add-iam-policy-binding phishnet-prod \
    --member="serviceAccount:phishnet-service@phishnet-prod.iam.gserviceaccount.com" \
    --role="roles/pubsub.subscriber"

# Download key
gcloud iam service-accounts keys create credentials/service-account.json \
    --iam-account=phishnet-service@phishnet-prod.iam.gserviceaccount.com
```

## SSL/TLS Configuration

### Using Let's Encrypt with Traefik
```yaml
# Add to docker-compose.prod.yml
services:
  traefik:
    image: traefik:v2.10
    command:
      - --certificatesresolvers.letsencrypt.acme.email=your-email@domain.com
      - --certificatesresolvers.letsencrypt.acme.storage=/acme.json
      - --certificatesresolvers.letsencrypt.acme.httpchallenge.entrypoint=web
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
      - ./acme.json:/acme.json
```

### Manual SSL Certificate
```bash
# Place certificates in ssl/ directory
ssl/
├── cert.pem
├── key.pem
└── ca.pem
```

## Monitoring & Logging

### Health Checks
- **API Health**: `GET /health`
- **System Status**: `GET /api/v1/status`
- **Metrics**: `GET /api/v1/metrics`

### Logging Configuration
```yaml
# docker-compose.prod.yml logging driver
logging:
  driver: "json-file"
  options:
    max-size: "10m"
    max-file: "3"
```

### Monitoring Endpoints
- WebSocket connections: `/api/v1/metrics`
- Queue lengths: Redis monitoring
- Worker health: Process status checks

## Backup Strategy

### Database Backup
```bash
# Automated backup script
#!/bin/bash
docker exec phishnet-postgres pg_dump -U phishnet phishnet | \
gzip > backup/phishnet-$(date +%Y%m%d).sql.gz

# Retention: Keep 30 days
find backup/ -name "*.sql.gz" -mtime +30 -delete
```

### Redis Backup
```bash
# Redis RDB snapshots
docker exec phishnet-redis redis-cli BGSAVE
```

## Scaling Guidelines

### Horizontal Scaling
```yaml
# Scale API service
docker-compose -f docker-compose.prod.yml up -d --scale api=3

# Scale workers based on load
EMAIL_WORKER_COUNT=5  # Process more emails
THREAT_WORKER_COUNT=3  # Handle threat analysis
```

### Performance Tuning
```yaml
# PostgreSQL optimizations
shared_buffers = 256MB
max_connections = 100
work_mem = 4MB

# Redis optimizations  
maxmemory 512mb
maxmemory-policy allkeys-lru
```

## Security Checklist

### Pre-deployment
- [ ] Generate strong SECRET_KEY (32+ characters)
- [ ] Create secure ENCRYPTION_KEY (Fernet.generate_key())
- [ ] Configure TLS/SSL certificates
- [ ] Validate OAuth redirect URIs
- [ ] Secure service account credentials
- [ ] Review firewall rules
- [ ] Enable audit logging

### Post-deployment
- [ ] Test OAuth flow end-to-end
- [ ] Verify webhook signature validation
- [ ] Test data export/deletion endpoints
- [ ] Validate rate limiting
- [ ] Check security headers
- [ ] Monitor error logs

## Troubleshooting

### Common Issues

**OAuth Flow Fails**
```bash
# Check redirect URI configuration
# Verify client ID/secret
# Check HTTPS configuration
docker-compose logs api | grep oauth
```

**Workers Not Processing**
```bash
# Check Redis connection
docker exec phishnet-redis redis-cli ping

# Check queue lengths
docker exec phishnet-redis redis-cli llen email_processing_queue

# Restart workers
docker-compose restart email-worker threat-worker
```

**Database Connection Issues**
```bash
# Check PostgreSQL status
docker-compose logs postgres

# Test connection
docker exec phishnet-postgres pg_isready -U phishnet
```

### Log Analysis
```bash
# API logs
docker-compose logs -f --tail=100 api

# Worker logs
docker-compose logs -f --tail=100 email-worker threat-worker

# System resource usage
docker stats
```

## API Documentation

### Authentication
All API endpoints require JWT authentication:
```bash
Authorization: Bearer <jwt-token>
```

### Key Endpoints
- `POST /api/v1/auth/gmail/init` - Initialize OAuth
- `GET /api/v1/auth/gmail/callback` - OAuth callback
- `GET /api/v1/scans` - Email scan history
- `GET /api/v1/dashboard/stats` - Dashboard statistics
- `POST /api/v1/quarantine/action` - Manual quarantine
- `GET /api/v1/privacy/export` - Export user data
- `POST /api/v1/privacy/delete` - Delete user data

### WebSocket
Real-time updates via WebSocket:
```javascript
const ws = new WebSocket('wss://yourdomain.com/api/v1/ws/USER_ID');
```

## Support & Maintenance

### Regular Maintenance
- Daily: Check service health and logs
- Weekly: Review security audit logs
- Monthly: Update dependencies and security patches
- Quarterly: Review and rotate API keys

### Emergency Procedures
- Service outage: Check docker-compose status
- Data breach: Execute incident response plan
- API rate limits: Scale workers or optimize queries

For additional support, refer to the technical documentation or create an issue in the repository.
