# Worker Queue Backlog Troubleshooting

**Severity Level**: Medium to High  
**Response Time**: 30 minutes  
**Resolution Time**: 1-2 hours

## Overview

Worker queue backlogs occur when email processing or analysis tasks accumulate faster than they can be processed, leading to delays in threat detection and user notifications.

## Detection and Monitoring

### Automated Alerts
```yaml
# Prometheus alert configuration
- alert: EmailQueueBacklog
  expr: phishnet_email_queue_size > 1000
  for: 10m
  labels:
    severity: warning
  annotations:
    summary: "Large email queue backlog detected"

- alert: AnalysisQueueBacklog  
  expr: phishnet_analysis_queue_size > 500
  for: 10m
  labels:
    severity: warning

- alert: WorkerProcessingStalled
  expr: rate(phishnet_emails_processed_total[5m]) == 0 and phishnet_email_queue_size > 0
  for: 15m
  labels:
    severity: critical
```

### Manual Detection
```bash
# Check current queue sizes
kubectl exec -n phishnet statefulset/redis -- redis-cli LLEN email_processing_queue
kubectl exec -n phishnet statefulset/redis -- redis-cli LLEN analysis_queue
kubectl exec -n phishnet statefulset/redis -- redis-cli LLEN notification_queue

# Check worker pod status
kubectl get pods -n phishnet -l component=worker

# Monitor real-time queue changes
watch -n 5 'kubectl exec -n phishnet statefulset/redis -- redis-cli LLEN email_processing_queue'
```

## Root Cause Analysis

### Common Causes

#### 1. Worker Pod Issues
```bash
# Check worker pod health
kubectl get pods -n phishnet -l component=worker -o wide

# Check worker logs for errors
kubectl logs -n phishnet deployment/phishnet-worker-email --tail=100 | grep -E "(ERROR|FATAL|Exception)"

# Check worker resource usage
kubectl top pods -n phishnet -l component=worker
```

#### 2. Database Connection Issues
```bash
# Check database connectivity from workers
kubectl exec -n phishnet deployment/phishnet-worker-email -- python -c "
import asyncio
from app.database import get_database
async def test():
    try:
        async with get_database() as db:
            await db.fetch_one('SELECT 1')
        print('✅ Database connection successful')
    except Exception as e:
        print(f'❌ Database connection failed: {e}')
asyncio.run(test())
"

# Check database connection pool status
kubectl logs -n phishnet statefulset/postgres | grep -E "(connection|pool)"
```

#### 3. External API Rate Limiting
```bash
# Check for API rate limit errors
kubectl logs -n phishnet deployment/phishnet-worker-analysis | grep -E "(rate.limit|quota|429|503)"

# Check specific API service status
kubectl exec -n phishnet deployment/phishnet-worker-analysis -- python -c "
from app.services.virustotal_service import VirusTotalService
from app.services.abuseipdb_service import AbuseIPDBService
print('VirusTotal:', VirusTotalService().check_quota())
print('AbuseIPDB:', AbuseIPDBService().check_quota())
"
```

#### 4. Memory/CPU Resource Constraints
```bash
# Check resource limits and requests
kubectl describe pods -n phishnet -l component=worker | grep -A 10 -B 5 "Limits:\|Requests:"

# Check HPA status
kubectl get hpa -n phishnet

# Check node resource availability
kubectl top nodes
kubectl describe nodes | grep -E "(Allocatable|Allocated resources)"
```

## Resolution Steps

### Immediate Mitigation

#### 1. Scale Worker Pods
```bash
# Increase worker replicas immediately
kubectl scale deployment phishnet-worker-email --replicas=6 -n phishnet
kubectl scale deployment phishnet-worker-analysis --replicas=4 -n phishnet

# Verify scaling
kubectl get deployments -n phishnet -l component=worker

# Check if pods are starting successfully
kubectl get pods -n phishnet -l component=worker
```

#### 2. Clear Stuck Jobs
```bash
# Identify stuck jobs (jobs without heartbeat for >10 minutes)
kubectl exec -n phishnet statefulset/redis -- redis-cli EVAL "
local stuck_jobs = {}
local processing_set = 'processing_jobs'
local jobs = redis.call('SMEMBERS', processing_set)
local current_time = redis.call('TIME')[1]

for _, job_id in ipairs(jobs) do
    local heartbeat = redis.call('GET', 'heartbeat:' .. job_id)
    if not heartbeat or (current_time - heartbeat) > 600 then
        table.insert(stuck_jobs, job_id)
        redis.call('SREM', processing_set, job_id)
        redis.call('DEL', 'heartbeat:' .. job_id)
    end
end
return stuck_jobs
" 0

# Requeue stuck jobs
kubectl exec -n phishnet statefulset/redis -- redis-cli EVAL "
local stuck_jobs = ARGV
for i = 1, #stuck_jobs do
    redis.call('LPUSH', 'email_processing_queue', stuck_jobs[i])
end
return #stuck_jobs
" 0 $(kubectl exec -n phishnet statefulset/redis -- redis-cli SMEMBERS processing_jobs)
```

#### 3. Restart Problematic Workers
```bash
# Identify workers with high error rates
kubectl logs -n phishnet deployment/phishnet-worker-email --tail=1000 | \
  grep ERROR | \
  awk '{print $1}' | \
  sort | uniq -c | sort -nr

# Restart specific worker pods
kubectl delete pods -n phishnet -l component=worker-email

# Or rolling restart
kubectl rollout restart deployment/phishnet-worker-email -n phishnet
kubectl rollout restart deployment/phishnet-worker-analysis -n phishnet
```

### Performance Optimization

#### 1. Adjust Worker Configuration
```bash
# Increase worker concurrency
kubectl patch configmap phishnet-config -n phishnet --patch='
data:
  WORKER_CONCURRENCY: "8"
  WORKER_BATCH_SIZE: "50"
  WORKER_TIMEOUT: "300"
'

# Update worker deployment to use new config
kubectl rollout restart deployment/phishnet-worker-email -n phishnet
kubectl rollout restart deployment/phishnet-worker-analysis -n phishnet
```

#### 2. Optimize Database Queries
```bash
# Check slow queries in worker operations
kubectl exec -n phishnet statefulset/postgres -- psql -U phishnet_user -d phishnet -c "
SELECT 
    query,
    mean_time,
    calls,
    total_time,
    min_time,
    max_time
FROM pg_stat_statements 
WHERE query LIKE '%email%' OR query LIKE '%analysis%'
ORDER BY mean_time DESC 
LIMIT 10;
"

# Check for missing indexes
kubectl exec -n phishnet statefulset/postgres -- psql -U phishnet_user -d phishnet -c "
SELECT 
    schemaname,
    tablename,
    attname,
    n_distinct,
    correlation
FROM pg_stats 
WHERE schemaname = 'public' 
  AND (tablename = 'emails' OR tablename = 'analysis_results')
ORDER BY correlation;
"
```

#### 3. Implement Circuit Breakers
```yaml
# Add circuit breaker configuration
apiVersion: v1
kind: ConfigMap
metadata:
  name: worker-circuit-breaker
  namespace: phishnet
data:
  circuit-breaker.yaml: |
    external_apis:
      virustotal:
        failure_threshold: 5
        timeout: 60
        retry_delay: 30
      abuseipdb:
        failure_threshold: 3
        timeout: 120
        retry_delay: 60
    database:
      failure_threshold: 10
      timeout: 30
      retry_delay: 5
```

### Long-term Solutions

#### 1. Implement Job Prioritization
```bash
# Create priority queues
kubectl exec -n phishnet statefulset/redis -- redis-cli EVAL "
-- Create priority queues
redis.call('DEL', 'high_priority_queue')
redis.call('DEL', 'normal_priority_queue') 
redis.call('DEL', 'low_priority_queue')
return 'Priority queues created'
" 0

# Update worker to process by priority
kubectl apply -f - << EOF
apiVersion: v1
kind: ConfigMap
metadata:
  name: worker-priority-config
  namespace: phishnet
data:
  priority-mapping.yaml: |
    priority_rules:
      - condition: "sender_reputation < 0.3"
        priority: "high"
      - condition: "contains_suspicious_links == true"
        priority: "high"
      - condition: "attachment_count > 0"
        priority: "normal"
      - condition: "default"
        priority: "low"
EOF
```

#### 2. Implement Auto-scaling
```yaml
# Enhanced HPA with custom metrics
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: phishnet-worker-email-hpa
  namespace: phishnet
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: phishnet-worker-email
  minReplicas: 2
  maxReplicas: 20
  metrics:
  - type: Resource
    resource:
      name: cpu
      target:
        type: Utilization
        averageUtilization: 70
  - type: Pods
    pods:
      metric:
        name: queue_size_per_pod
      target:
        type: AverageValue
        averageValue: "100"
  behavior:
    scaleUp:
      stabilizationWindowSeconds: 60
      policies:
      - type: Percent
        value: 100
        periodSeconds: 15
    scaleDown:
      stabilizationWindowSeconds: 300
      policies:
      - type: Percent
        value: 10
        periodSeconds: 60
```

#### 3. Add Queue Monitoring Dashboard
```yaml
# Grafana dashboard configuration
apiVersion: v1
kind: ConfigMap
metadata:
  name: queue-monitoring-dashboard
  namespace: phishnet
data:
  dashboard.json: |
    {
      "dashboard": {
        "title": "PhishNet Queue Monitoring",
        "panels": [
          {
            "title": "Queue Sizes",
            "type": "graph",
            "targets": [
              {
                "expr": "phishnet_email_queue_size",
                "legendFormat": "Email Queue"
              },
              {
                "expr": "phishnet_analysis_queue_size", 
                "legendFormat": "Analysis Queue"
              }
            ]
          },
          {
            "title": "Processing Rate",
            "type": "graph", 
            "targets": [
              {
                "expr": "rate(phishnet_emails_processed_total[5m])",
                "legendFormat": "Emails/sec"
              }
            ]
          },
          {
            "title": "Worker Status",
            "type": "stat",
            "targets": [
              {
                "expr": "up{job=\"phishnet-workers\"}",
                "legendFormat": "Workers Up"
              }
            ]
          }
        ]
      }
    }
```

## Monitoring and Prevention

### Real-time Monitoring
```bash
# Set up continuous monitoring script
cat > monitor-queues.sh << 'EOF'
#!/bin/bash
while true; do
    EMAIL_QUEUE=$(kubectl exec -n phishnet statefulset/redis -- redis-cli LLEN email_processing_queue)
    ANALYSIS_QUEUE=$(kubectl exec -n phishnet statefulset/redis -- redis-cli LLEN analysis_queue)
    WORKERS=$(kubectl get pods -n phishnet -l component=worker --no-headers | grep Running | wc -l)
    
    echo "$(date): Email Queue: $EMAIL_QUEUE, Analysis Queue: $ANALYSIS_QUEUE, Workers: $WORKERS"
    
    # Alert if queue size exceeds threshold
    if [ $EMAIL_QUEUE -gt 1000 ]; then
        echo "WARNING: Email queue backlog detected!"
        # Send alert to monitoring system
    fi
    
    sleep 30
done
EOF

chmod +x monitor-queues.sh
```

### Predictive Scaling
```python
# Implement predictive scaling based on historical patterns
# Add to app/workers/autoscaler.py
import pandas as pd
from datetime import datetime, timedelta

class QueuePredictor:
    def __init__(self):
        self.historical_data = self.load_historical_data()
    
    def predict_queue_size(self, timestamp):
        # Analyze patterns: time of day, day of week
        hour = timestamp.hour
        weekday = timestamp.weekday()
        
        # Get historical average for this time period
        similar_periods = self.historical_data[
            (self.historical_data['hour'] == hour) & 
            (self.historical_data['weekday'] == weekday)
        ]
        
        return similar_periods['queue_size'].mean()
    
    def recommend_scaling(self, predicted_queue_size):
        # Calculate recommended worker count
        emails_per_worker_per_minute = 50
        target_processing_time = 10  # minutes
        
        required_workers = max(2, int(predicted_queue_size / 
                                    (emails_per_worker_per_minute * target_processing_time)))
        
        return min(required_workers, 20)  # Cap at 20 workers
```

### Capacity Planning
```bash
# Analyze queue patterns for capacity planning
kubectl exec -n phishnet statefulset/redis -- redis-cli EVAL "
local queue_samples = {}
local current_time = redis.call('TIME')[1]

-- Sample queue sizes every hour for the last 7 days
for i = 0, 167 do  -- 24 * 7 = 168 hours
    local timestamp = current_time - (i * 3600)
    local queue_size = redis.call('GET', 'queue_size_sample:' .. timestamp) or 0
    table.insert(queue_samples, {timestamp, queue_size})
end

return queue_samples
" 0
```

## Escalation Procedures

### When to Escalate
- Queue backlog exceeds 5,000 items for more than 2 hours
- Worker scaling doesn't resolve the issue within 1 hour
- Critical business emails are delayed beyond SLA (>30 minutes)
- External API services are completely unavailable

### Escalation Actions
1. **Level 1**: Senior DevOps Engineer
   - Advanced troubleshooting
   - Infrastructure optimization
   - Vendor coordination

2. **Level 2**: Engineering Team Lead + Product Owner
   - Business impact assessment
   - Resource allocation decisions
   - Customer communication

3. **Level 3**: CTO + Customer Success
   - Executive decision making
   - Public communication
   - Vendor escalation

### Emergency Procedures
```bash
# Emergency queue drain (use with caution)
# This script processes emails with minimal analysis for urgent situations

kubectl apply -f - << EOF
apiVersion: batch/v1
kind: Job
metadata:
  name: emergency-queue-drain
  namespace: phishnet
spec:
  template:
    spec:
      containers:
      - name: emergency-processor
        image: phishnet/worker:latest
        command: ["python", "-m", "app.workers.emergency_processor"]
        env:
        - name: EMERGENCY_MODE
          value: "true"
        - name: SKIP_DETAILED_ANALYSIS
          value: "true"
      restartPolicy: Never
  backoffLimit: 3
EOF
```

## Post-Resolution

### Performance Analysis
```bash
# Generate post-incident report
cat > queue-backlog-report.md << EOF
## Queue Backlog Incident Report

**Date**: $(date)
**Duration**: [Fill in duration]
**Peak Queue Size**: [Fill in peak size]
**Root Cause**: [Fill in analysis]

### Timeline
- Detection: [timestamp]
- Mitigation Started: [timestamp]  
- Resolution: [timestamp]

### Actions Taken
- [List all actions]

### Lessons Learned
- [Key takeaways]

### Prevention Measures
- [Specific improvements]
EOF
```

### System Improvements
1. **Update monitoring thresholds** based on incident learnings
2. **Adjust auto-scaling parameters** to prevent future backlogs
3. **Implement additional circuit breakers** for external dependencies
4. **Review and update worker resource limits**
5. **Schedule capacity planning review**

### Testing Recovery Procedures
```bash
# Schedule monthly queue stress tests
kubectl apply -f - << EOF
apiVersion: batch/v1
kind: CronJob
metadata:
  name: queue-stress-test
  namespace: phishnet
spec:
  schedule: "0 2 1 * *"  # First day of month at 2 AM
  jobTemplate:
    spec:
      template:
        spec:
          containers:
          - name: stress-test
            image: phishnet/test-tools:latest
            command: ["python", "-m", "app.tests.queue_stress_test"]
          restartPolicy: OnFailure
EOF
```
