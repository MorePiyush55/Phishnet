# Deployment Procedures

**Document Version**: 1.0  
**Last Updated**: September 12, 2025  
**Review Cycle**: Quarterly

## Overview

This document outlines the deployment procedures for PhishNet across different environments, including automated CI/CD processes and manual deployment procedures.

## Deployment Environments

### Environment Matrix
| Environment | Purpose | Deployment Method | Approval Required |
|-------------|---------|-------------------|-------------------|
| Development | Feature development | Automatic on push to `develop` | No |
| Staging | Integration testing | Automatic on push to `main` | No |
| Production | Live system | Manual trigger after staging tests | Yes |

### Environment Configuration
```bash
# Development
ENVIRONMENT=development
REPLICAS_API=1
REPLICAS_WORKER=1
RESOURCE_LIMITS_CPU=500m
RESOURCE_LIMITS_MEMORY=1Gi

# Staging  
ENVIRONMENT=staging
REPLICAS_API=2
REPLICAS_WORKER=2
RESOURCE_LIMITS_CPU=1
RESOURCE_LIMITS_MEMORY=2Gi

# Production
ENVIRONMENT=production
REPLICAS_API=3
REPLICAS_WORKER=4
RESOURCE_LIMITS_CPU=2
RESOURCE_LIMITS_MEMORY=4Gi
```

## Automated Deployment (CI/CD)

### GitHub Actions Workflow
The automated deployment pipeline is defined in `.github/workflows/ci-cd.yml`:

#### Trigger Conditions
- **Development**: Push to `develop` branch
- **Staging**: Push to `main` branch  
- **Production**: Manual workflow dispatch with approval

#### Pipeline Stages
1. **Build & Test** (5-10 minutes)
   - Code compilation
   - Unit tests
   - Integration tests
   - Security scans

2. **Container Build** (3-5 minutes)
   - Docker image build
   - Vulnerability scanning
   - Push to registry

3. **Deploy to Staging** (2-3 minutes)
   - Helm deployment
   - Database migrations
   - Smoke tests

4. **Production Approval** (Manual)
   - Stakeholder approval
   - Change management validation

5. **Deploy to Production** (5-10 minutes)
   - Blue-green deployment
   - Health checks
   - Rollback on failure

### Monitoring Pipeline Status
```bash
# Check pipeline status
gh workflow list --repo yourorg/phishnet

# View specific run
gh run view <run-id> --repo yourorg/phishnet

# Check deployment status
kubectl get deployments -n phishnet-staging
kubectl get deployments -n phishnet-production
```

## Manual Deployment Procedures

### Prerequisites
```bash
# Required tools
kubectl version --client
helm version
docker version

# Verify cluster access
kubectl cluster-info
kubectl auth can-i create deployments --namespace=phishnet-production

# Verify image availability
docker pull phishnet/api:v1.2.0
docker pull phishnet/worker:v1.2.0
```

### Pre-Deployment Checklist
- [ ] Code reviewed and approved
- [ ] All tests passing
- [ ] Security scan completed
- [ ] Database migrations tested
- [ ] Rollback plan prepared
- [ ] Stakeholders notified
- [ ] Maintenance window scheduled (if required)

### Staging Deployment
```bash
#!/bin/bash
# staging-deploy.sh

set -e

VERSION=${1:-latest}
NAMESPACE=phishnet-staging

echo "Deploying PhishNet version $VERSION to staging..."

# 1. Update Helm values for staging
cat > staging-values.yaml << EOF
image:
  tag: $VERSION

replicaCount:
  api: 2
  worker: 2

environment: staging

resources:
  api:
    limits:
      cpu: 1
      memory: 2Gi
    requests:
      cpu: 500m
      memory: 1Gi

ingress:
  enabled: true
  hosts:
    - host: staging.phishnet.yourcompany.com
      paths:
        - path: /
          pathType: Prefix
EOF

# 2. Deploy with Helm
helm upgrade --install phishnet-staging ./helm/phishnet \
  --namespace $NAMESPACE \
  --create-namespace \
  --values staging-values.yaml \
  --wait \
  --timeout 10m

# 3. Verify deployment
kubectl rollout status deployment/phishnet-api -n $NAMESPACE
kubectl rollout status deployment/phishnet-worker-email -n $NAMESPACE

# 4. Run smoke tests
kubectl apply -f k8s/tests/staging-smoke-tests.yaml
kubectl wait --for=condition=complete job/staging-smoke-tests -n $NAMESPACE --timeout=300s

echo "Staging deployment completed successfully!"
```

### Production Deployment

#### Blue-Green Deployment Strategy
```bash
#!/bin/bash
# production-deploy.sh

set -e

VERSION=${1:?Version required}
NAMESPACE=phishnet-production
CURRENT_COLOR=$(kubectl get service phishnet-api -n $NAMESPACE -o jsonpath='{.spec.selector.color}' || echo "blue")
NEW_COLOR=$([ "$CURRENT_COLOR" = "blue" ] && echo "green" || echo "blue")

echo "Deploying PhishNet version $VERSION to production ($NEW_COLOR slot)..."

# 1. Create production values
cat > production-values.yaml << EOF
image:
  tag: $VERSION

replicaCount:
  api: 3
  worker: 4

environment: production

color: $NEW_COLOR

resources:
  api:
    limits:
      cpu: 2
      memory: 4Gi
    requests:
      cpu: 1
      memory: 2Gi

ingress:
  enabled: true
  hosts:
    - host: phishnet.yourcompany.com
      paths:
        - path: /
          pathType: Prefix

monitoring:
  enabled: true
  
backup:
  enabled: true
EOF

# 2. Pre-deployment backup
echo "Creating pre-deployment backup..."
kubectl create job --from=cronjob/postgres-backup pre-deploy-backup-$(date +%Y%m%d-%H%M) -n $NAMESPACE

# 3. Deploy to new color slot
helm upgrade --install phishnet-$NEW_COLOR ./helm/phishnet \
  --namespace $NAMESPACE \
  --values production-values.yaml \
  --wait \
  --timeout 15m

# 4. Verify new deployment health
echo "Verifying deployment health..."
kubectl rollout status deployment/phishnet-api-$NEW_COLOR -n $NAMESPACE
kubectl rollout status deployment/phishnet-worker-email-$NEW_COLOR -n $NAMESPACE

# 5. Run production smoke tests against new deployment
sed "s/COLOR_PLACEHOLDER/$NEW_COLOR/g" k8s/tests/production-smoke-tests.yaml | kubectl apply -f -
kubectl wait --for=condition=complete job/production-smoke-tests-$NEW_COLOR -n $NAMESPACE --timeout=600s

# 6. Switch traffic to new deployment
echo "Switching traffic to $NEW_COLOR deployment..."
kubectl patch service phishnet-api -n $NAMESPACE -p '{"spec":{"selector":{"color":"'$NEW_COLOR'"}}}'

# 7. Wait and monitor for issues
echo "Monitoring new deployment for 5 minutes..."
sleep 300

# 8. Check error rates and performance
ERROR_RATE=$(curl -s "http://prometheus:9090/api/v1/query?query=rate(http_requests_total{status=~'5..'}[5m])" | jq -r '.data.result[0].value[1] // 0')
if (( $(echo "$ERROR_RATE > 0.01" | bc -l) )); then
    echo "High error rate detected ($ERROR_RATE). Rolling back..."
    kubectl patch service phishnet-api -n $NAMESPACE -p '{"spec":{"selector":{"color":"'$CURRENT_COLOR'"}}}'
    exit 1
fi

# 9. Clean up old deployment after successful switch
echo "Cleaning up old deployment ($CURRENT_COLOR)..."
helm uninstall phishnet-$CURRENT_COLOR -n $NAMESPACE

echo "Production deployment completed successfully!"
```

### Rollback Procedures

#### Immediate Rollback (Emergency)
```bash
#!/bin/bash
# emergency-rollback.sh

NAMESPACE=phishnet-production
CURRENT_COLOR=$(kubectl get service phishnet-api -n $NAMESPACE -o jsonpath='{.spec.selector.color}')
PREVIOUS_COLOR=$([ "$CURRENT_COLOR" = "blue" ] && echo "green" || echo "blue")

echo "Emergency rollback initiated..."

# 1. Switch traffic back to previous deployment
kubectl patch service phishnet-api -n $NAMESPACE -p '{"spec":{"selector":{"color":"'$PREVIOUS_COLOR'"}}}'

# 2. Verify rollback
kubectl get service phishnet-api -n $NAMESPACE -o jsonpath='{.spec.selector.color}'

# 3. Monitor health
curl -f https://phishnet.yourcompany.com/health

echo "Emergency rollback completed. Active color: $PREVIOUS_COLOR"
```

#### Planned Rollback
```bash
#!/bin/bash
# planned-rollback.sh

VERSION=${1:?Previous version required}
NAMESPACE=phishnet-production

echo "Rolling back to version $VERSION..."

# 1. Check rollout history
kubectl rollout history deployment/phishnet-api -n $NAMESPACE

# 2. Rollback using Helm
helm rollback phishnet $VERSION -n $NAMESPACE --wait

# 3. Verify rollback
kubectl rollout status deployment/phishnet-api -n $NAMESPACE

# 4. Run smoke tests
kubectl apply -f k8s/tests/rollback-verification-tests.yaml
kubectl wait --for=condition=complete job/rollback-verification-tests -n $NAMESPACE --timeout=300s

echo "Planned rollback to version $VERSION completed!"
```

## Database Migration Procedures

### Pre-Migration Steps
```bash
#!/bin/bash
# pre-migration.sh

NAMESPACE=phishnet-production

echo "Preparing for database migration..."

# 1. Create backup
kubectl create job --from=cronjob/postgres-backup migration-backup-$(date +%Y%m%d-%H%M) -n $NAMESPACE

# 2. Verify backup completion
kubectl wait --for=condition=complete job/migration-backup-$(date +%Y%m%d-%H%M) -n $NAMESPACE --timeout=1800s

# 3. Test migration on staging database
kubectl exec -n phishnet-staging statefulset/postgres -- psql -U phishnet_user -d phishnet -f /sql/migrations/latest.sql

echo "Pre-migration steps completed"
```

### Migration Execution
```bash
#!/bin/bash
# run-migration.sh

NAMESPACE=phishnet-production

echo "Running database migration..."

# 1. Put application in maintenance mode
kubectl scale deployment phishnet-api --replicas=0 -n $NAMESPACE
kubectl scale deployment phishnet-worker-email --replicas=0 -n $NAMESPACE

# 2. Deploy maintenance page
kubectl apply -f k8s/maintenance/maintenance-page.yaml

# 3. Run migration
kubectl exec -n $NAMESPACE statefulset/postgres -- psql -U phishnet_user -d phishnet -f /sql/migrations/latest.sql

# 4. Verify migration
kubectl exec -n $NAMESPACE statefulset/postgres -- psql -U phishnet_user -d phishnet -c "\\dt"

# 5. Restore application
kubectl scale deployment phishnet-api --replicas=3 -n $NAMESPACE
kubectl scale deployment phishnet-worker-email --replicas=4 -n $NAMESPACE

# 6. Remove maintenance page
kubectl delete -f k8s/maintenance/maintenance-page.yaml

echo "Database migration completed"
```

## Configuration Management

### Environment-Specific Configurations
```yaml
# configs/development.yaml
database:
  host: postgres.phishnet-dev.svc.cluster.local
  ssl_mode: disable
  max_connections: 20

redis:
  host: redis.phishnet-dev.svc.cluster.local
  ssl: false
  max_connections: 100

logging:
  level: DEBUG
  format: json

# configs/production.yaml  
database:
  host: postgres.phishnet-production.svc.cluster.local
  ssl_mode: require
  max_connections: 100

redis:
  host: redis.phishnet-production.svc.cluster.local
  ssl: true
  max_connections: 500

logging:
  level: INFO
  format: structured
```

### Secret Management
```bash
# Sync secrets from external secret manager
kubectl apply -f k8s/secret-management/external-secret-store.yaml

# Verify secret synchronization
kubectl get externalsecrets -n phishnet-production
kubectl describe externalsecret phishnet-api-secrets -n phishnet-production

# Test secret access
kubectl exec -n phishnet-production deployment/phishnet-api -- env | grep -E "(API_KEY|SECRET)"
```

## Monitoring Deployment Health

### Health Check Endpoints
```bash
# API Health
curl -f https://phishnet.yourcompany.com/health
curl -f https://phishnet.yourcompany.com/ready

# Worker Health  
kubectl exec -n phishnet-production deployment/phishnet-worker-email -- curl -f http://localhost:8002/health

# Database Health
kubectl exec -n phishnet-production statefulset/postgres -- pg_isready -U phishnet_user
```

### Metrics Validation
```bash
# Check key metrics after deployment
curl -s "http://prometheus:9090/api/v1/query?query=up{job='phishnet-api'}" | jq '.data.result[0].value[1]'

# API response times
curl -s "http://prometheus:9090/api/v1/query?query=histogram_quantile(0.95,http_request_duration_seconds_bucket)" | jq '.data.result[0].value[1]'

# Error rates
curl -s "http://prometheus:9090/api/v1/query?query=rate(http_requests_total{status=~'5..'}[5m])" | jq '.data.result[0].value[1]'
```

### Deployment Dashboard
```yaml
# Grafana dashboard for deployments
{
  "dashboard": {
    "title": "PhishNet Deployments",
    "panels": [
      {
        "title": "Deployment Status",
        "type": "stat",
        "targets": [
          {
            "expr": "kube_deployment_status_replicas_available{deployment=~'phishnet-.*'}",
            "legendFormat": "{{deployment}}"
          }
        ]
      },
      {
        "title": "Rollout Progress", 
        "type": "graph",
        "targets": [
          {
            "expr": "kube_deployment_status_replicas_updated{deployment=~'phishnet-.*'}",
            "legendFormat": "Updated - {{deployment}}"
          }
        ]
      }
    ]
  }
}
```

## Troubleshooting Deployment Issues

### Common Issues and Solutions

#### 1. Image Pull Errors
```bash
# Check image availability
docker pull phishnet/api:v1.2.0

# Verify registry credentials
kubectl get secrets -n phishnet-production | grep regcred
kubectl describe secret regcred -n phishnet-production

# Fix image pull secrets
kubectl patch serviceaccount default -n phishnet-production -p '{"imagePullSecrets": [{"name": "regcred"}]}'
```

#### 2. Resource Constraints
```bash
# Check node resources
kubectl top nodes
kubectl describe nodes | grep -A 10 "Allocated resources"

# Check pod resource usage
kubectl top pods -n phishnet-production

# Adjust resource requests/limits
kubectl patch deployment phishnet-api -n phishnet-production -p '
spec:
  template:
    spec:
      containers:
      - name: phishnet-api
        resources:
          requests:
            memory: "1Gi"
            cpu: "500m"
          limits:
            memory: "2Gi" 
            cpu: "1"
'
```

#### 3. Configuration Errors
```bash
# Validate ConfigMap
kubectl get configmap phishnet-config -n phishnet-production -o yaml

# Check secret availability
kubectl get secrets -n phishnet-production
kubectl describe secret phishnet-secrets -n phishnet-production

# Test configuration
kubectl exec -n phishnet-production deployment/phishnet-api -- python -c "
from app.config import settings
print('Database URL:', settings.database_url[:20] + '...')
print('Redis URL:', settings.redis_url[:20] + '...')
"
```

#### 4. Network Issues
```bash
# Check service discovery
kubectl get services -n phishnet-production
kubectl get endpoints -n phishnet-production

# Test internal connectivity
kubectl exec -n phishnet-production deployment/phishnet-api -- nslookup postgres.phishnet-production.svc.cluster.local

# Check ingress
kubectl get ingress -n phishnet-production
kubectl describe ingress phishnet-ingress -n phishnet-production
```

## Post-Deployment Procedures

### Validation Checklist
- [ ] All pods running and ready
- [ ] Health checks passing
- [ ] Key metrics within normal ranges
- [ ] No increase in error rates
- [ ] Database connectivity verified
- [ ] External API integrations working
- [ ] Queue processing resumed
- [ ] Monitoring alerts not firing

### Communication
```bash
# Notify stakeholders of successful deployment
curl -X POST -H 'Content-type: application/json' \
  --data '{
    "text": "✅ PhishNet v'$VERSION' deployed successfully to production",
    "attachments": [
      {
        "color": "good",
        "fields": [
          {"title": "Version", "value": "'$VERSION'", "short": true},
          {"title": "Environment", "value": "Production", "short": true},
          {"title": "Deployment Time", "value": "'$(date)'", "short": false}
        ]
      }
    ]
  }' \
  $SLACK_WEBHOOK_URL
```

### Documentation Updates
```bash
# Update deployment history
echo "$(date): Deployed version $VERSION to production" >> deployment-history.log

# Update runbook if procedures changed
git add docs/runbooks/deployment-procedures.md
git commit -m "Update deployment procedures after v$VERSION deployment"
git push
```

## Disaster Recovery

### Backup Restoration
```bash
# Restore from backup (emergency procedure)
kubectl create job restore-from-backup --image=postgres:15-alpine -n phishnet-production -- /bin/bash -c "
pg_restore -h postgres.phishnet-production.svc.cluster.local -U phishnet_user -d phishnet /backups/latest-backup.sql
"
```

### Cross-Region Failover
```bash
# Switch to disaster recovery region
helm install phishnet-dr ./helm/phishnet \
  --namespace phishnet-production \
  --values configs/disaster-recovery.yaml \
  --set global.primary=false \
  --set global.dr_mode=true
```

This completes the comprehensive deployment procedures documentation.
