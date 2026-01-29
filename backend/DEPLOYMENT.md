# Mode 1 Production Deployment - Complete Guide

## 🎯 Objective
Deploy Mode 1 to production with full monitoring, secrets management, and validation.

## ✅ Prerequisites Checklist

Before running deployment:

- [ ] Production environment provisioned (AWS/GCP/Azure)
- [ ] MongoDB cluster running and accessible
- [ ] Redis cluster running and accessible
- [ ] Docker installed on deployment machine
- [ ] kubectl configured (if using Kubernetes)
- [ ] AWS CLI configured (if using AWS Secrets Manager)
- [ ] Slack webhook URL obtained
- [ ] PagerDuty service key obtained
- [ ] SSL certificates obtained
- [ ] Domain DNS configured

## 🚀 One-Command Deployment

```bash
cd backend
chmod +x scripts/deploy_production.sh
./scripts/deploy_production.sh
```

This automated script will:
1. ✅ Deploy monitoring stack (Prometheus, Grafana, Alertmanager)
2. ✅ Configure secrets in AWS Secrets Manager
3. ✅ Create MongoDB indexes
4. ✅ Run full test suite
5. ✅ Deploy application
6. ✅ Verify health checks

## 📊 Post-Deployment Verification

### 1. Check Monitoring

```bash
# Prometheus
open http://localhost:9090

# Grafana (admin/admin)
open http://localhost:3000

# Alertmanager
open http://localhost:9093
```

### 2. Verify Mode 1 Status

```bash
curl http://localhost:8000/api/v1/mode1/status | jq
```

Expected output:
```json
{
  "running": true,
  "active_jobs": 0,
  "polling_tasks": ["default"],
  "resilience": {
    "circuit_breakers": {
      "imap": "closed",
      "virustotal": "closed",
      "gemini": "closed"
    }
  }
}
```

### 3. Check Pipeline Metrics

```bash
curl http://localhost:8000/api/v1/mode1/pipeline/stats | jq
```

### 4. Run Load Tests

```bash
# Normal load (100 emails/hour)
locust -f tests/load/mode1_load_test.py \
  --host=http://localhost:8000 \
  --users=10 \
  --spawn-rate=1 \
  --run-time=10m \
  --html=load-test-report.html

# Peak load (1000 emails/hour)
locust -f tests/load/mode1_load_test.py \
  --host=http://localhost:8000 \
  --users=100 \
  --spawn-rate=10 \
  --run-time=10m \
  --html=peak-load-report.html
```

## 🔐 Secrets Configuration

### AWS Secrets Manager

Create secrets JSON files:

**secrets/imap-credentials.json**:
```json
{
  "user": "phishnet@example.com",
  "password": "your-app-password"
}
```

**secrets/api-keys.json**:
```json
{
  "virustotal": "your-vt-key",
  "gemini": "your-gemini-key",
  "abuseipdb": "your-abuseipdb-key"
}
```

Then run:
```bash
aws secretsmanager create-secret \
  --name phishnet/mode1/imap/default \
  --secret-string file://secrets/imap-credentials.json

aws secretsmanager create-secret \
  --name phishnet/mode1/api-keys \
  --secret-string file://secrets/api-keys.json
```

## 📈 Grafana Dashboard Setup

1. Login to Grafana (http://localhost:3000)
2. Go to Dashboards → Import
3. Import `grafana/dashboards/mode1-pipeline.json`
4. Select Prometheus datasource

## 🚨 Alert Configuration

### Slack

1. Create Slack webhook: https://api.slack.com/messaging/webhooks
2. Update `docker/monitoring/alertmanager.yml`:
   ```yaml
   global:
     slack_api_url: 'https://hooks.slack.com/services/YOUR/WEBHOOK/URL'
   ```
3. Restart Alertmanager:
   ```bash
   docker-compose -f docker/monitoring/docker-compose.yml restart alertmanager
   ```

### PagerDuty

1. Get service key from PagerDuty
2. Update `docker/monitoring/alertmanager.yml`:
   ```yaml
   receivers:
     - name: 'pagerduty'
       pagerduty_configs:
         - service_key: 'YOUR_PAGERDUTY_SERVICE_KEY'
   ```
3. Restart Alertmanager

## 🧪 Test Coverage Report

After deployment, view test coverage:

```bash
# Run tests with coverage
python -m pytest tests/ -v --cov=app --cov-report=html

# Open coverage report
open htmlcov/index.html
```

Target: **>80% coverage**

## 📋 Production Readiness Checklist

### Code ✅
- [x] All 8 hardening phases complete
- [x] Real metrics integration
- [x] IMAP coordination locks
- [x] Prometheus metrics
- [x] Secrets manager abstraction
- [x] Test suite created
- [x] Load testing scripts

### Infrastructure (Run deployment script)
- [ ] Monitoring stack deployed
- [ ] Secrets configured
- [ ] Database indexes created
- [ ] Tests passing (100%)
- [ ] Load tests passing
- [ ] Alerts configured
- [ ] Grafana dashboards imported

### Validation
- [ ] Health checks passing
- [ ] Circuit breakers working
- [ ] Rate limiters working
- [ ] Deduplication working
- [ ] Policy engine working
- [ ] Audit logging working

## 🎉 Success Criteria

Mode 1 is production-ready when:

1. ✅ Deployment script completes without errors
2. ✅ All tests pass (100%)
3. ✅ Load tests handle 1000+ emails/hour
4. ✅ p95 latency < 30 seconds
5. ✅ Circuit breakers respond to failures
6. ✅ Alerts fire correctly
7. ✅ Grafana dashboards show metrics
8. ✅ No memory leaks over 24 hours

## 🆘 Troubleshooting

### Deployment fails
```bash
# Check logs
docker-compose -f docker/monitoring/docker-compose.yml logs

# Check application logs
kubectl logs -f deployment/phishnet-backend
```

### Tests fail
```bash
# Run specific test
python -m pytest tests/unit/test_fake_imap_client.py -v

# Check test environment
python -c "from app.config.settings import get_settings; print(get_settings())"
```

### Monitoring not working
```bash
# Restart monitoring stack
docker-compose -f docker/monitoring/docker-compose.yml restart

# Check Prometheus targets
open http://localhost:9090/targets
```

## 📞 Support

- Documentation: `docs/MODE1_INFRASTRUCTURE_SETUP.md`
- Runbook: See infrastructure setup guide
- On-call: PagerDuty rotation
