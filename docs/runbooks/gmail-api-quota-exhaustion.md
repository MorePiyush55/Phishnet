# Gmail API Quota Exhaustion Incident Response

## Overview
This runbook provides step-by-step procedures for handling Gmail API quota exhaustion incidents in the PhishNet system.

## Incident Classification
- **Severity**: High (Service disruption)
- **Impact**: Email analysis workers unable to process emails
- **Type**: External service limitation

## Detection and Alerting

### Symptoms
- Email analysis workers reporting 429 errors (Too Many Requests)
- Increased error rates in Prometheus metrics
- Backlog of unprocessed emails in Redis queues
- Worker logs showing quota exhaustion messages

### Monitoring Alerts
```yaml
# Prometheus Alert
- alert: GmailAPIQuotaExceeded
  expr: increase(gmail_api_requests_total{status="429"}[5m]) > 10
  for: 2m
  labels:
    severity: high
    service: email-worker
  annotations:
    summary: "Gmail API quota exceeded"
    description: "Gmail API quota exhaustion detected - {{ $value }} 429 errors in 5 minutes"
```

### Key Metrics to Monitor
- `gmail_api_requests_total{status="429"}` - Quota exceeded errors
- `gmail_api_requests_per_minute` - Current API usage rate
- `email_processing_queue_size` - Backlog of pending emails
- `worker_error_rate` - Overall worker error rate

## Immediate Response (0-15 minutes)

### 1. Acknowledge the Incident
```bash
# Check current GMT time for quota reset timing
date -u

# Verify incident in monitoring dashboard
# Navigate to Grafana Gmail API dashboard
```

### 2. Assess Impact
```bash
# Check email queue backlog
kubectl exec -n phishnet redis-0 -- redis-cli llen email_analysis_queue

# Check active worker status
kubectl get pods -n phishnet -l app=phishnet-worker-email

# Review recent error logs
kubectl logs -n phishnet deployment/phishnet-worker-email --since=10m | grep -i quota
```

### 3. Implement Immediate Mitigation

#### Scale Down Email Workers (Preserve Quota)
```bash
# Temporarily scale down email workers to prevent further quota consumption
kubectl scale deployment phishnet-worker-email --replicas=0 -n phishnet

# Verify workers are stopped
kubectl get pods -n phishnet -l app=phishnet-worker-email
```

#### Enable Circuit Breaker (If Available)
```bash
# Update ConfigMap to enable circuit breaker
kubectl patch configmap phishnet-worker-config -n phishnet -p '{"data":{"GMAIL_API_CIRCUIT_BREAKER":"true"}}'

# Restart workers with circuit breaker enabled
kubectl rollout restart deployment/phishnet-worker-email -n phishnet
```

## Investigation (15-30 minutes)

### 1. Determine Quota Status
```bash
# Check Gmail API quotas in Google Cloud Console
# Navigate to: Google Cloud Console > APIs & Services > Quotas
# Search for "Gmail API" quotas

# Common quota limits:
# - Requests per day: 1,000,000,000
# - Requests per minute per user: 250
# - Requests per second per user: 10
```

### 2. Analyze Usage Patterns
```bash
# Check recent API usage metrics
kubectl exec -n phishnet deployment/phishnet-api -- curl -s "http://prometheus:9090/api/v1/query?query=rate(gmail_api_requests_total[1h])"

# Review worker logs for unusual patterns
kubectl logs -n phishnet deployment/phishnet-worker-email --since=1h | grep -E "(rate|quota|limit)" | head -20

# Check for any runaway processes or loops
kubectl top pods -n phishnet --sort-by=cpu
```

### 3. Identify Root Cause
Common causes:
- **Burst traffic**: Sudden influx of emails to analyze
- **Inefficient code**: New deployment with increased API calls
- **Retry loops**: Failed requests being retried excessively
- **Configuration error**: Wrong rate limiting configuration

## Resolution (30-60 minutes)

### 1. Wait for Quota Reset (If Near Reset Time)
```bash
# Gmail API quotas reset at midnight Pacific Time (08:00 UTC)
# Calculate time until quota reset
CURRENT_UTC=$(date -u +%H:%M)
echo "Current UTC time: $CURRENT_UTC"
echo "Quota resets at 08:00 UTC"

# If within 2 hours of reset, consider waiting
if [ $(date -u +%H) -ge 6 ]; then
  echo "Consider waiting for quota reset"
fi
```

### 2. Implement Rate Limiting (Immediate Fix)
```bash
# Update worker configuration with conservative rate limits
cat << EOF | kubectl apply -f -
apiVersion: v1
kind: ConfigMap
metadata:
  name: phishnet-worker-config
  namespace: phishnet
data:
  GMAIL_API_RATE_LIMIT: "5"  # Requests per second
  GMAIL_API_BURST_LIMIT: "10"  # Burst capacity
  GMAIL_API_BACKOFF_ENABLED: "true"
  GMAIL_API_RETRY_MAX: "3"
  GMAIL_API_RETRY_DELAY: "30"  # seconds
EOF

# Restart workers with new configuration
kubectl rollout restart deployment/phishnet-worker-email -n phishnet
```

### 3. Scale Up Gradually
```bash
# Start with minimal workers
kubectl scale deployment phishnet-worker-email --replicas=1 -n phishnet

# Wait 5 minutes and monitor
sleep 300

# Check for quota errors
kubectl logs -n phishnet deployment/phishnet-worker-email --since=5m | grep -i quota

# If no errors, gradually increase
kubectl scale deployment phishnet-worker-email --replicas=2 -n phishnet

# Continue monitoring and scaling as needed
```

### 4. Alternative Solutions

#### Use Service Account Impersonation
```bash
# If using domain-wide delegation, rotate between service accounts
kubectl patch deployment phishnet-worker-email -n phishnet -p '
{
  "spec": {
    "template": {
      "spec": {
        "containers": [
          {
            "name": "worker",
            "env": [
              {
                "name": "GMAIL_SERVICE_ACCOUNT_KEY",
                "valueFrom": {
                  "secretKeyRef": {
                    "name": "gmail-service-account-2",
                    "key": "credentials.json"
                  }
                }
              }
            ]
          }
        ]
      }
    }
  }
}'
```

#### Enable Batch Processing
```bash
# Configure workers to process emails in batches
kubectl patch configmap phishnet-worker-config -n phishnet -p '{"data":{"BATCH_SIZE":"10","BATCH_DELAY":"60"}}'

kubectl rollout restart deployment/phishnet-worker-email -n phishnet
```

## Recovery Verification (60-90 minutes)

### 1. Monitor Key Metrics
```bash
# Check quota error rate (should be 0)
kubectl exec -n phishnet deployment/phishnet-api -- curl -s "http://prometheus:9090/api/v1/query?query=rate(gmail_api_requests_total{status=\"429\"}[5m])"

# Monitor email processing rate
kubectl exec -n phishnet redis-0 -- redis-cli llen email_analysis_queue

# Check worker health
kubectl get pods -n phishnet -l app=phishnet-worker-email
```

### 2. Process Backlog
```bash
# Estimate backlog processing time
QUEUE_SIZE=$(kubectl exec -n phishnet redis-0 -- redis-cli llen email_analysis_queue)
PROCESSING_RATE=5  # emails per minute per worker
WORKER_COUNT=$(kubectl get deployment phishnet-worker-email -n phishnet -o jsonpath='{.spec.replicas}')

ESTIMATED_TIME=$((QUEUE_SIZE / (PROCESSING_RATE * WORKER_COUNT)))
echo "Estimated backlog processing time: $ESTIMATED_TIME minutes"

# If backlog is large, consider temporarily increasing workers
if [ $QUEUE_SIZE -gt 1000 ]; then
  echo "Large backlog detected. Consider scaling workers to 3-5 replicas"
  kubectl scale deployment phishnet-worker-email --replicas=3 -n phishnet
fi
```

### 3. Performance Testing
```bash
# Send test email for processing
kubectl exec -n phishnet deployment/phishnet-api -- curl -X POST \
  -H "Content-Type: application/json" \
  -d '{"email_content": "test email for quota recovery", "priority": "low"}' \
  http://localhost:8000/api/v1/emails/analyze

# Monitor test processing
kubectl logs -n phishnet deployment/phishnet-worker-email --follow
```

## Post-Incident Actions (90+ minutes)

### 1. Update Monitoring
```bash
# Add proactive quota monitoring
cat << EOF | kubectl apply -f -
apiVersion: monitoring.coreos.com/v1
kind: PrometheusRule
metadata:
  name: gmail-quota-monitoring
  namespace: phishnet
spec:
  groups:
  - name: gmail-api-quota
    rules:
    - alert: GmailAPIQuotaWarning
      expr: rate(gmail_api_requests_total[5m]) * 60 > 200  # 80% of 250/minute limit
      for: 5m
      labels:
        severity: warning
      annotations:
        summary: "Gmail API quota usage high"
        description: "Gmail API usage at {{ \$value }} requests/minute (limit: 250)"
    
    - alert: GmailAPIQuotaCritical
      expr: rate(gmail_api_requests_total[5m]) * 60 > 240  # 96% of 250/minute limit
      for: 2m
      labels:
        severity: critical
      annotations:
        summary: "Gmail API quota usage critical"
        description: "Gmail API usage at {{ \$value }} requests/minute - quota exhaustion imminent"
EOF
```

### 2. Implement Long-term Solutions

#### Request Quota Increase
```bash
# Document quota increase request
cat << EOF > /tmp/quota-increase-request.md
# Gmail API Quota Increase Request

## Current Limits
- Requests per minute per user: 250
- Requests per day: 1,000,000,000

## Requested Limits
- Requests per minute per user: 500
- Justification: PhishNet processes high volume of suspicious emails for security analysis

## Business Impact
- Current limits cause service disruptions during peak usage
- Delayed email analysis reduces security effectiveness
- Customer satisfaction impact due to processing delays

## Usage Patterns
- Average: 180 requests/minute
- Peak: 300 requests/minute
- Daily volume: 250,000 requests
EOF

echo "Submit quota increase request through Google Cloud Console"
```

#### Implement Smart Rate Limiting
```bash
# Deploy enhanced rate limiting configuration
cat << EOF | kubectl apply -f -
apiVersion: v1
kind: ConfigMap
metadata:
  name: phishnet-rate-limiter-config
  namespace: phishnet
data:
  config.yaml: |
    rate_limiter:
      gmail_api:
        base_rate: 4  # requests per second (conservative)
        burst_size: 8
        adaptive_scaling: true
        backoff_strategy: "exponential"
        circuit_breaker:
          enabled: true
          threshold: 10  # failures before opening circuit
          timeout: 60    # seconds before retry
        quota_tracking:
          enabled: true
          warning_threshold: 0.8
          critical_threshold: 0.95
EOF
```

### 3. Update Documentation
```bash
# Update incident response documentation
cat << EOF >> docs/runbooks/incident-response-summary.md
## Gmail API Quota Exhaustion Incident - $(date)

### Summary
- **Duration**: X hours
- **Root Cause**: [Detailed cause]
- **Impact**: [Business impact]
- **Resolution**: [Steps taken]

### Lessons Learned
- [Key insights]
- [Process improvements]

### Action Items
- [ ] Implement proactive quota monitoring
- [ ] Request quota increase from Google
- [ ] Enhance rate limiting algorithms
- [ ] Add circuit breaker patterns
EOF
```

## Prevention Measures

### 1. Proactive Monitoring
- Set quota warning alerts at 80% usage
- Monitor API request patterns for anomalies
- Track quota utilization trends

### 2. Rate Limiting Best Practices
- Implement exponential backoff for retries
- Use circuit breaker patterns
- Distribute requests across multiple service accounts (if applicable)

### 3. Capacity Planning
- Regular quota usage analysis
- Predictive scaling based on email volume
- Load testing with realistic scenarios

## Communication Templates

### Internal Notification
```
Subject: RESOLVED - Gmail API Quota Exhaustion Incident

Team,

We have resolved the Gmail API quota exhaustion incident that occurred at [TIME].

Impact: Email analysis workers were temporarily unable to process emails due to API rate limits.
Resolution: Implemented rate limiting and gradually scaled workers back up.
Duration: [X] hours

The backlog of [X] emails is being processed and should be cleared within [X] minutes.

Next steps:
- Monitoring quota usage closely
- Implementing enhanced rate limiting
- Requesting quota increase from Google

- Operations Team
```

### Customer Communication (if applicable)
```
Subject: Service Status Update - Email Analysis Delays Resolved

We have resolved temporary delays in email analysis processing that occurred today between [TIME RANGE].

What happened: We experienced Gmail API rate limiting during peak usage.
Impact: Email analysis was delayed by approximately [X] minutes.
Resolution: We implemented enhanced rate limiting and processing has resumed normally.

All pending emails have been processed and the service is operating normally.

Thank you for your patience.
```

## Escalation Contacts

- **Primary On-call**: DevOps team lead
- **Secondary**: Platform engineering manager  
- **Gmail API Expert**: [Specific team member]
- **Executive Escalation**: CTO (for major business impact)

## Related Documentation

- [Gmail API Documentation](https://developers.google.com/gmail/api)
- [Rate Limiting Best Practices](../architecture/rate-limiting.md)
- [Monitoring Playbook](./monitoring-playbook.md)
- [Incident Response Procedures](./incident-response.md)
