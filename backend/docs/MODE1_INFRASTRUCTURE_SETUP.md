# Mode 1 Production Infrastructure Setup Guide

This document provides step-by-step instructions for setting up the infrastructure required for Mode 1 production deployment.

## Prerequisites

- [ ] Production environment provisioned (AWS/GCP/Azure)
- [ ] Database instances running (MongoDB, Redis)
- [ ] Network security configured
- [ ] SSL certificates obtained

---

## 1. Monitoring and Alerting Setup

### 1.1 Prometheus Installation

```bash
# Using Docker
docker run -d \
  --name prometheus \
  -p 9090:9090 \
  -v /path/to/prometheus.yml:/etc/prometheus/prometheus.yml \
  prom/prometheus

# Or using Kubernetes
kubectl apply -f k8s/prometheus-deployment.yaml
```

**Prometheus Configuration** (`prometheus.yml`):
```yaml
global:
  scrape_interval: 15s

scrape_configs:
  - job_name: 'phishnet-mode1'
    static_configs:
      - targets: ['phishnet-backend:8000']
    metrics_path: '/metrics'
```

### 1.2 Grafana Dashboards

```bash
# Install Grafana
docker run -d \
  --name grafana \
  -p 3000:3000 \
  grafana/grafana

# Import Mode 1 dashboard
# Dashboard JSON available in: docs/grafana-dashboard.json
```

**Key Metrics to Monitor**:
- `mode1_emails_processed_total` - Email throughput
- `mode1_stage_duration_seconds` - Stage latency (p95, p99)
- `mode1_circuit_breaker_state` - Circuit breaker health
- `mode1_active_jobs` - Concurrent processing load

### 1.3 Alerting Rules

**PagerDuty Integration**:
```yaml
# alertmanager.yml
route:
  receiver: 'pagerduty'
  
receivers:
  - name: 'pagerduty'
    pagerduty_configs:
      - service_key: '<YOUR_PAGERDUTY_KEY>'
```

**Critical Alerts**:
1. Circuit breaker open > 5 minutes
2. Email processing latency p95 > 30 seconds
3. Error rate > 5%
4. Active jobs > 100 (backpressure)

---

## 2. Secrets Manager Configuration

### 2.1 AWS Secrets Manager

```bash
# Create secret for IMAP credentials
aws secretsmanager create-secret \
  --name phishnet/mode1/imap/default \
  --secret-string '{"user":"phishnet@example.com","password":"app-password"}'

# Create secret for API keys
aws secretsmanager create-secret \
  --name phishnet/mode1/api-keys \
  --secret-string '{"virustotal":"xxx","gemini":"yyy","abuseipdb":"zzz"}'
```

**Application Configuration**:
```bash
SECRETS_PROVIDER=aws
AWS_REGION=us-east-1
AWS_SECRET_NAME=phishnet/mode1/imap/default
```

### 2.2 GCP Secret Manager

```bash
# Create secret
echo -n '{"user":"phishnet@example.com","password":"app-password"}' | \
  gcloud secrets create phishnet-mode1-imap --data-file=-

# Grant access
gcloud secrets add-iam-policy-binding phishnet-mode1-imap \
  --member="serviceAccount:phishnet@project.iam.gserviceaccount.com" \
  --role="roles/secretmanager.secretAccessor"
```

**Application Configuration**:
```bash
SECRETS_PROVIDER=gcp
GCP_PROJECT_ID=your-project-id
GCP_SECRET_NAME=phishnet-mode1-imap
```

### 2.3 HashiCorp Vault

```bash
# Enable KV secrets engine
vault secrets enable -path=phishnet kv-v2

# Store IMAP credentials
vault kv put phishnet/mode1/imap/default \
  user=phishnet@example.com \
  password=app-password

# Create policy
vault policy write phishnet-mode1 - <<EOF
path "phishnet/mode1/*" {
  capabilities = ["read"]
}
EOF
```

**Application Configuration**:
```bash
SECRETS_PROVIDER=vault
VAULT_ADDR=https://vault.example.com
VAULT_TOKEN=<service-token>
```

---

## 3. Load Testing

### 3.1 Test Environment Setup

```bash
# Deploy to staging
kubectl apply -f k8s/staging/

# Scale to production-like resources
kubectl scale deployment phishnet-backend --replicas=3
```

### 3.2 Load Test Scenarios

**Scenario 1: Normal Load (100 emails/hour)**
```bash
# Using Locust
locust -f tests/load/mode1_load_test.py \
  --host=https://staging.phishnet.example.com \
  --users=10 \
  --spawn-rate=1 \
  --run-time=1h
```

**Scenario 2: Peak Load (1000 emails/hour)**
```bash
locust -f tests/load/mode1_load_test.py \
  --users=100 \
  --spawn-rate=10 \
  --run-time=1h
```

**Scenario 3: Stress Test (Circuit Breaker Validation)**
```bash
# Simulate VirusTotal rate limit
locust -f tests/load/circuit_breaker_test.py \
  --users=200 \
  --spawn-rate=20
```

### 3.3 Success Criteria

- [ ] p95 latency < 30 seconds at 1000 emails/hour
- [ ] Circuit breakers open/close correctly under load
- [ ] No memory leaks (stable memory usage over 24 hours)
- [ ] Backpressure activates at > 100 concurrent jobs
- [ ] System recovers gracefully from dependency failures

---

## 4. Security Audit

### 4.1 Code Review Checklist

- [ ] No hardcoded credentials
- [ ] SQL injection prevention (using ORMs)
- [ ] Input validation on all API endpoints
- [ ] Rate limiting enabled
- [ ] CORS configured correctly
- [ ] Authentication required for admin endpoints
- [ ] Audit logging for all sensitive operations

### 4.2 Dependency Audit

```bash
# Python dependencies
pip-audit

# Check for known vulnerabilities
safety check

# Update dependencies
pip install --upgrade -r requirements.txt
```

### 4.3 Penetration Testing

**Tools**:
- OWASP ZAP for API testing
- Burp Suite for manual testing
- Nmap for network scanning

**Test Areas**:
1. Authentication bypass attempts
2. SQL injection
3. XSS attacks
4. CSRF protection
5. Rate limit bypass
6. Secrets exposure

### 4.4 Compliance Validation

**GDPR Requirements**:
- [ ] Data encryption at rest
- [ ] Data encryption in transit (TLS 1.3)
- [ ] Right to deletion implemented
- [ ] Data retention policies configured
- [ ] Audit trail for data access

**SOC 2 Requirements**:
- [ ] Access controls documented
- [ ] Change management process
- [ ] Incident response plan
- [ ] Business continuity plan

---

## 5. Database Optimization

### 5.1 MongoDB Indexes

```javascript
// Create indexes for Mode 1 collections
db.content_hashes.createIndex({ "message_id_hash": 1, "tenant_id": 1 }, { unique: true })
db.content_hashes.createIndex({ "created_at": 1 }, { expireAfterSeconds: 2592000 }) // 30 days TTL

db.mailbox_configs.createIndex({ "tenant_id": 1 }, { unique: true })
db.mailbox_configs.createIndex({ "status": 1 })

db.mode1_audit_logs.createIndex({ "tenant_id": 1, "timestamp": -1 })
db.mode1_audit_logs.createIndex({ "event_type": 1 })
```

### 5.2 Redis Configuration

```conf
# redis.conf
maxmemory 2gb
maxmemory-policy allkeys-lru
save 900 1
save 300 10
save 60 10000
```

---

## 6. Deployment Checklist

### Pre-Deployment
- [ ] All tests passing (unit, integration, load)
- [ ] Secrets configured in secrets manager
- [ ] Monitoring dashboards created
- [ ] Alerting rules configured
- [ ] Database indexes created
- [ ] Redis tuned
- [ ] Security audit completed
- [ ] Runbook documented

### Deployment
- [ ] Deploy to staging
- [ ] Smoke test in staging
- [ ] Load test in staging
- [ ] Blue-green deployment to production
- [ ] Monitor metrics for 24 hours
- [ ] Verify alerting works

### Post-Deployment
- [ ] Document any issues encountered
- [ ] Update runbook with lessons learned
- [ ] Schedule post-mortem meeting
- [ ] Plan for next iteration

---

## 7. Runbook

### Common Issues

**Circuit Breaker Stuck Open**
```bash
# Check circuit breaker state
curl https://api.phishnet.example.com/api/v1/mode1/status

# Manual reset (if needed)
curl -X POST https://api.phishnet.example.com/api/v1/mode1/circuit-breaker/reset
```

**High Latency**
```bash
# Check bottlenecks
curl https://api.phishnet.example.com/api/v1/mode1/pipeline/bottlenecks

# Check active jobs
curl https://api.phishnet.example.com/api/v1/mode1/status | jq '.active_jobs'
```

**IMAP Connection Failures**
```bash
# Check mailbox status
curl https://api.phishnet.example.com/api/v1/mode1/mailboxes

# Deactivate problematic mailbox
curl -X PUT https://api.phishnet.example.com/api/v1/mode1/mailboxes/{tenant_id}/deactivate
```

---

## Contact

For production support:
- On-call: PagerDuty rotation
- Slack: #phishnet-mode1-alerts
- Email: devops@example.com
