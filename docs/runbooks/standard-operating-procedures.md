# Standard Operating Procedures (SOPs)

**Document Version**: 1.0  
**Last Updated**: September 12, 2025  
**Review Cycle**: Quarterly

## Overview

This document outlines the standard operating procedures for PhishNet production operations, covering routine tasks, emergency responses, and best practices.

## Daily Operations

### Morning Health Check (9:00 AM)
```bash
#!/bin/bash
# daily-health-check.sh

echo "=== PhishNet Daily Health Check - $(date) ==="

# 1. Check all pods are running
echo "1. Checking pod status..."
kubectl get pods -n phishnet --no-headers | grep -v Running | wc -l
if [ $? -eq 0 ]; then
    echo "✅ All pods running normally"
else
    echo "❌ Some pods not running - investigate immediately"
    kubectl get pods -n phishnet | grep -v Running
fi

# 2. Check service endpoints
echo "2. Checking service health..."
for service in api webhook worker-email worker-analysis; do
    if kubectl get endpoints phishnet-$service -n phishnet | grep -q "none"; then
        echo "❌ $service has no endpoints"
    else
        echo "✅ $service endpoints available"
    fi
done

# 3. Check database connectivity
echo "3. Checking database..."
kubectl exec -n phishnet deployment/phishnet-api -- python -c "
import asyncio
from app.database import get_database
async def check():
    async with get_database() as db:
        result = await db.fetch_one('SELECT 1 as test')
        print('✅ Database connection successful')
asyncio.run(check())
"

# 4. Check Redis connectivity
echo "4. Checking Redis..."
kubectl exec -n phishnet statefulset/redis -- redis-cli ping
if [ $? -eq 0 ]; then
    echo "✅ Redis responding"
else
    echo "❌ Redis not responding"
fi

# 5. Check queue sizes
echo "5. Checking queue sizes..."
EMAIL_QUEUE=$(kubectl exec -n phishnet statefulset/redis -- redis-cli LLEN email_processing_queue)
ANALYSIS_QUEUE=$(kubectl exec -n phishnet statefulset/redis -- redis-cli LLEN analysis_queue)
echo "Email processing queue: $EMAIL_QUEUE"
echo "Analysis queue: $ANALYSIS_QUEUE"

if [ $EMAIL_QUEUE -gt 1000 ]; then
    echo "⚠️ Email queue backlog detected"
fi

# 6. Check recent errors
echo "6. Checking for recent errors..."
ERROR_COUNT=$(kubectl logs -n phishnet deployment/phishnet-api --since=24h | grep -i error | wc -l)
echo "Errors in last 24h: $ERROR_COUNT"

if [ $ERROR_COUNT -gt 100 ]; then
    echo "⚠️ High error rate detected"
fi

echo "=== Health check completed ==="
```

### Security Monitoring (Every 4 hours)
```bash
#!/bin/bash
# security-monitoring.sh

echo "=== Security Monitoring Check - $(date) ==="

# 1. Check for suspicious login attempts
echo "1. Checking authentication logs..."
kubectl logs -n phishnet deployment/phishnet-api --since=4h | \
  grep -E "(authentication_failed|suspicious_login)" | \
  wc -l

# 2. Check for unusual API access patterns
echo "2. Checking API access patterns..."
kubectl logs -n phishnet deployment/phishnet-api --since=4h | \
  grep "rate_limit_exceeded" | \
  awk '{print $6}' | sort | uniq -c | sort -nr | head -10

# 3. Monitor threat detection rates
echo "3. Checking threat detection rates..."
THREATS_DETECTED=$(kubectl logs -n phishnet deployment/phishnet-worker-analysis --since=4h | \
  grep "threat_detected" | wc -l)
echo "Threats detected in last 4h: $THREATS_DETECTED"

# 4. Check for data exfiltration attempts
echo "4. Checking for data exfiltration..."
kubectl logs -n phishnet deployment/phishnet-api --since=4h | \
  grep -E "(large_data_request|bulk_export)" | \
  head -5

echo "=== Security monitoring completed ==="
```

## Weekly Operations

### System Performance Review (Monday 10:00 AM)
```bash
#!/bin/bash
# weekly-performance-review.sh

echo "=== Weekly Performance Review - $(date) ==="

# 1. Resource utilization
echo "1. Resource Utilization Summary:"
kubectl top nodes
kubectl top pods -n phishnet --sort-by=cpu

# 2. Database performance
echo "2. Database Performance:"
kubectl exec -n phishnet statefulset/postgres -- psql -U phishnet_user -d phishnet -c "
SELECT 
    schemaname,
    tablename,
    attname,
    n_distinct,
    correlation
FROM pg_stats 
WHERE schemaname = 'public' 
ORDER BY n_distinct DESC 
LIMIT 10;
"

# 3. Queue processing times
echo "3. Queue Processing Analysis:"
kubectl logs -n phishnet deployment/phishnet-worker-email --since=168h | \
  grep "processing_time" | \
  awk '{print $8}' | \
  sort -n | \
  awk '{sum+=$1; count++} END {print "Average processing time:", sum/count, "seconds"}'

# 4. API response times
echo "4. API Performance:"
kubectl logs -n phishnet deployment/phishnet-api --since=168h | \
  grep "response_time" | \
  awk '{print $7}' | \
  sort -n | \
  awk '{
    a[NR]=$1;
    sum+=$1
  } 
  END {
    print "Average:", sum/NR;
    print "Median:", (NR%2==0) ? (a[NR/2]+a[NR/2+1])/2 : a[(NR+1)/2];
    print "95th percentile:", a[int(NR*0.95)]
  }'

echo "=== Performance review completed ==="
```

### Security Audit (Friday 2:00 PM)
```bash
#!/bin/bash
# weekly-security-audit.sh

echo "=== Weekly Security Audit - $(date) ==="

# 1. Check for CVEs in running containers
echo "1. Container Security Scan:"
for deployment in api webhook worker-email worker-analysis; do
    echo "Scanning phishnet-$deployment..."
    # This would integrate with your vulnerability scanner
    # trivy image $(kubectl get deployment phishnet-$deployment -n phishnet -o jsonpath='{.spec.template.spec.containers[0].image}')
done

# 2. Review access patterns
echo "2. Access Pattern Review:"
kubectl logs -n phishnet deployment/phishnet-api --since=168h | \
  grep "user_action" | \
  awk '{print $5}' | \
  sort | uniq -c | sort -nr | head -20

# 3. Check certificate expiry
echo "3. Certificate Expiry Check:"
kubectl get secrets -n phishnet -o json | \
  jq -r '.items[] | select(.type=="kubernetes.io/tls") | .metadata.name' | \
  while read cert; do
    kubectl get secret $cert -n phishnet -o jsonpath='{.data.tls\.crt}' | \
      base64 -d | \
      openssl x509 -noout -enddate
  done

echo "=== Security audit completed ==="
```

## Emergency Response Procedures

### System Down Response
**Response Time**: 5 minutes  
**Severity**: Critical

#### Immediate Actions (0-5 minutes)
1. **Confirm Outage**
   ```bash
   # Check external monitoring
   curl -f https://phishnet.yourcompany.com/health
   
   # Check internal status
   kubectl get pods -n phishnet
   kubectl get services -n phishnet
   ```

2. **Activate Incident Response**
   ```bash
   # Notify stakeholders
   curl -X POST -H 'Content-type: application/json' \
     --data '{"text":"🚨 CRITICAL: PhishNet system down. Incident response activated."}' \
     $SLACK_WEBHOOK_URL
   
   # Create incident ticket
   # [Integration with your ticketing system]
   ```

3. **Check Infrastructure**
   ```bash
   # Check node health
   kubectl get nodes
   kubectl describe nodes | grep -E "(Ready|MemoryPressure|DiskPressure)"
   
   # Check cluster resources
   kubectl top nodes
   kubectl get events -n phishnet --sort-by='.lastTimestamp'
   ```

#### Investigation (5-15 minutes)
1. **Analyze Logs**
   ```bash
   # Recent application logs
   kubectl logs -n phishnet deployment/phishnet-api --tail=100
   
   # System events
   kubectl get events -n phishnet --sort-by='.lastTimestamp' | head -20
   
   # Resource exhaustion check
   kubectl describe pods -n phishnet | grep -E "(Warning|Error|Failed)"
   ```

2. **Database Connectivity**
   ```bash
   # Check database pod
   kubectl get pods -n phishnet -l component=database
   kubectl logs -n phishnet statefulset/postgres --tail=50
   
   # Test connection
   kubectl exec -n phishnet statefulset/postgres -- pg_isready
   ```

3. **Network Issues**
   ```bash
   # Check service endpoints
   kubectl get endpoints -n phishnet
   
   # DNS resolution
   kubectl exec -n phishnet deployment/phishnet-api -- nslookup postgres.phishnet.svc.cluster.local
   ```

#### Resolution Actions
1. **Restart Services**
   ```bash
   # Rolling restart of API
   kubectl rollout restart deployment/phishnet-api -n phishnet
   
   # Check rollout status
   kubectl rollout status deployment/phishnet-api -n phishnet
   ```

2. **Scale Resources**
   ```bash
   # Increase replicas if resource contention
   kubectl scale deployment phishnet-api --replicas=5 -n phishnet
   
   # Check HPA status
   kubectl get hpa -n phishnet
   ```

3. **Fallback to Previous Version**
   ```bash
   # Check rollout history
   kubectl rollout history deployment/phishnet-api -n phishnet
   
   # Rollback if needed
   kubectl rollout undo deployment/phishnet-api -n phishnet
   ```

### Performance Degradation Response
**Response Time**: 15 minutes  
**Severity**: High

#### Detection
- Response times > 5 seconds
- Queue backlog > 10,000 items
- CPU utilization > 80%
- Memory utilization > 85%

#### Actions
1. **Scale Horizontally**
   ```bash
   # Increase API replicas
   kubectl scale deployment phishnet-api --replicas=6 -n phishnet
   
   # Increase worker replicas
   kubectl scale deployment phishnet-worker-email --replicas=4 -n phishnet
   kubectl scale deployment phishnet-worker-analysis --replicas=3 -n phishnet
   ```

2. **Database Optimization**
   ```bash
   # Check slow queries
   kubectl exec -n phishnet statefulset/postgres -- psql -U phishnet_user -d phishnet -c "
   SELECT query, mean_time, calls, total_time 
   FROM pg_stat_statements 
   ORDER BY mean_time DESC 
   LIMIT 10;
   "
   
   # Check locks
   kubectl exec -n phishnet statefulset/postgres -- psql -U phishnet_user -d phishnet -c "
   SELECT pid, usename, application_name, state, query 
   FROM pg_stat_activity 
   WHERE state != 'idle';
   "
   ```

3. **Cache Optimization**
   ```bash
   # Check Redis memory usage
   kubectl exec -n phishnet statefulset/redis -- redis-cli info memory
   
   # Clear cache if needed (last resort)
   # kubectl exec -n phishnet statefulset/redis -- redis-cli FLUSHDB
   ```

## Maintenance Windows

### Scheduled Maintenance Procedure
**Frequency**: Monthly  
**Duration**: 2 hours  
**Window**: Saturday 2:00 AM - 4:00 AM UTC

#### Pre-Maintenance (T-24 hours)
1. **Notify Users**
   ```bash
   # Send maintenance notification
   curl -X POST -H 'Content-type: application/json' \
     --data '{"text":"📅 Scheduled maintenance: PhishNet will be unavailable Saturday 2:00-4:00 AM UTC for system updates."}' \
     $SLACK_WEBHOOK_URL
   ```

2. **Backup Verification**
   ```bash
   # Verify latest backup
   kubectl get jobs -n phishnet | grep backup
   kubectl logs -n phishnet job/postgres-backup-$(date +%Y%m%d) --tail=20
   ```

3. **Prepare Rollback Plan**
   ```bash
   # Document current versions
   kubectl get deployments -n phishnet -o wide > current_versions.txt
   kubectl get configmaps -n phishnet -o yaml > current_configs.yaml
   ```

#### During Maintenance
1. **Enable Maintenance Mode**
   ```bash
   # Scale down user-facing services
   kubectl scale deployment phishnet-api --replicas=0 -n phishnet
   kubectl scale deployment phishnet-webhook --replicas=0 -n phishnet
   
   # Deploy maintenance page
   kubectl apply -f k8s/maintenance/maintenance-page.yaml
   ```

2. **Perform Updates**
   ```bash
   # Update database schema
   kubectl exec -n phishnet statefulset/postgres -- psql -U phishnet_user -d phishnet -f /sql/migrations/latest.sql
   
   # Update application images
   kubectl set image deployment/phishnet-api phishnet-api=phishnet/api:v1.2.0 -n phishnet
   kubectl set image deployment/phishnet-worker-email phishnet-worker-email=phishnet/worker:v1.2.0 -n phishnet
   ```

3. **Validate Updates**
   ```bash
   # Check deployment status
   kubectl rollout status deployment/phishnet-api -n phishnet
   
   # Run smoke tests
   kubectl apply -f k8s/tests/smoke-tests.yaml
   kubectl wait --for=condition=complete job/smoke-tests -n phishnet --timeout=300s
   ```

#### Post-Maintenance
1. **Restore Service**
   ```bash
   # Scale up services
   kubectl scale deployment phishnet-api --replicas=3 -n phishnet
   kubectl scale deployment phishnet-webhook --replicas=2 -n phishnet
   
   # Remove maintenance page
   kubectl delete -f k8s/maintenance/maintenance-page.yaml
   ```

2. **Monitor Health**
   ```bash
   # Watch for errors
   kubectl logs -n phishnet deployment/phishnet-api --tail=50 -f
   
   # Check metrics
   curl -s http://prometheus:9090/api/v1/query?query=up{job="phishnet-api"}
   ```

## Communication Protocols

### Incident Communication
1. **Initial Notification** (Within 5 minutes)
   - Slack #incidents channel
   - Email to on-call engineers
   - Update status page

2. **Hourly Updates** (During active incident)
   - Progress summary
   - ETA for resolution
   - Impact assessment

3. **Resolution Notification**
   - All clear message
   - Summary of actions taken
   - Link to post-incident report

### Stakeholder Matrix
| Severity | Engineering | Product | Customer Success | Executive |
|----------|-------------|---------|------------------|-----------|
| Critical | Immediate   | 15 min  | 30 min          | 1 hour    |
| High     | 15 min      | 1 hour  | 2 hours         | 4 hours   |
| Medium   | 1 hour      | 4 hours | Next day        | Weekly    |
| Low      | 4 hours     | Next day| Weekly          | Monthly   |

## Documentation Updates

### Procedure Updates
- Update runbooks after each incident
- Review procedures quarterly
- Test emergency procedures monthly
- Update contact information monthly

### Version Control
- All procedures stored in Git
- Changes require peer review
- Tag releases for major updates
- Maintain change log

## Training and Certification

### Required Training
- New team members: Complete all SOPs within 30 days
- Existing team: Quarterly refresher training
- Incident response: Monthly drills

### Certification Requirements
- Kubernetes administration
- Database management
- Security incident response
- Application troubleshooting

## Compliance and Auditing

### Audit Trail
- All production changes logged
- Access logs retained for 1 year
- Procedure execution documented
- Security events archived

### Compliance Checks
- SOC 2 Type II requirements
- GDPR data handling procedures
- Industry security standards
- Internal security policies
