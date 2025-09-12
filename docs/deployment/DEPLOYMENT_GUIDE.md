# PhishNet Enterprise Deployment Guide

## 🚀 Quick Start Enterprise Deployment

### Prerequisites
- Docker & Docker Compose
- Kubernetes cluster (1.21+)
- Helm 3.x
- kubectl configured
- Python 3.11+

### 1. Development Environment Setup

```bash
# Clone repository
git clone https://github.com/your-org/phishnet.git
cd phishnet

# Start development environment
docker-compose up -d

# Verify all services
docker-compose ps
python validate_enterprise_readiness.py
```

### 2. Production Deployment

#### Option A: Kubernetes with Helm (Recommended)

```bash
# Add secrets (replace with your values)
kubectl create namespace phishnet
kubectl create secret generic phishnet-secrets \
  --from-literal=POSTGRES_PASSWORD="your-secure-password" \
  --from-literal=REDIS_PASSWORD="your-redis-password" \
  --from-literal=SECRET_KEY="your-secret-key" \
  --from-literal=GMAIL_CLIENT_ID="your-gmail-client-id" \
  --from-literal=GMAIL_CLIENT_SECRET="your-gmail-client-secret" \
  --from-literal=VIRUSTOTAL_API_KEY="your-virustotal-key" \
  -n phishnet

# Deploy with Helm
helm install phishnet ./helm/phishnet \
  --namespace phishnet \
  --values ./helm/phishnet/values-production.yaml

# Verify deployment
kubectl get pods -n phishnet
kubectl get services -n phishnet
```

#### Option B: Direct Kubernetes Manifests

```bash
# Apply manifests in order
kubectl apply -f k8s/base/namespace.yaml
kubectl apply -f k8s/base/secrets-config.yaml
kubectl apply -f k8s/base/postgres.yaml
kubectl apply -f k8s/base/redis.yaml
kubectl apply -f k8s/base/api-deployment.yaml
kubectl apply -f k8s/base/worker-deployment.yaml
kubectl apply -f k8s/base/ingress.yaml

# Monitor rollout
kubectl rollout status deployment/phishnet-api -n phishnet
```

### 3. Monitoring & Observability

```bash
# Enable monitoring stack
docker-compose --profile monitoring up -d

# Access dashboards
echo "Grafana: http://localhost:3000 (admin/admin)"
echo "Prometheus: http://localhost:9090"
echo "Jaeger: http://localhost:16686"
```

### 4. Backup & Recovery

```bash
# Setup automated backups
kubectl apply -f k8s/base/backup-cronjob.yaml

# Manual backup
kubectl create job --from=cronjob/database-backup manual-backup-$(date +%Y%m%d) -n phishnet

# Restore from backup
./scripts/restore.sh /path/to/backup.sql.gz
```

### 5. Health & Validation

```bash
# Comprehensive validation
python validate_enterprise_readiness.py

# Health checks
curl http://localhost:8000/health
curl http://localhost:8000/health/readiness
curl http://localhost:8000/health/liveness

# Load testing
python test_health_probes.py
```

## 📋 Production Checklist

### Security
- [ ] Secrets properly configured and not in source code
- [ ] TLS/SSL certificates configured
- [ ] Network policies applied
- [ ] RBAC permissions configured
- [ ] Security scanning enabled in CI/CD
- [ ] Container images scanned for vulnerabilities

### Reliability
- [ ] Health probes configured (liveness, readiness, startup)
- [ ] Resource limits and requests set
- [ ] Horizontal Pod Autoscaler configured
- [ ] Rolling update strategy configured
- [ ] Graceful shutdown implemented
- [ ] Circuit breakers for external APIs

### Observability
- [ ] Metrics collection (Prometheus)
- [ ] Distributed tracing (Jaeger)
- [ ] Log aggregation (ELK stack)
- [ ] Alerting rules configured
- [ ] Dashboards created (Grafana)
- [ ] SLO/SLI monitoring

### Backup & Recovery
- [ ] Automated database backups
- [ ] Backup retention policies
- [ ] Recovery procedures tested
- [ ] Disaster recovery plan
- [ ] Cross-region replication (if required)

### Operations
- [ ] CI/CD pipeline functional
- [ ] Automated testing in pipeline
- [ ] Staging environment available
- [ ] Rollback procedures tested
- [ ] Incident response runbooks
- [ ] On-call procedures defined

## 🛠 Troubleshooting

### Common Issues

#### Pod Not Starting
```bash
kubectl describe pod <pod-name> -n phishnet
kubectl logs <pod-name> -n phishnet
```

#### Database Connection Issues
```bash
kubectl exec -it postgres-0 -n phishnet -- psql -U phishnet_user -d phishnet
```

#### High Memory Usage
```bash
kubectl top pods -n phishnet
kubectl describe hpa phishnet-api -n phishnet
```

### Performance Tuning

#### Database Optimization
```sql
-- Monitor slow queries
SELECT query, mean_time, calls, total_time 
FROM pg_stat_statements 
ORDER BY total_time DESC LIMIT 10;

-- Optimize connections
ALTER SYSTEM SET max_connections = 200;
ALTER SYSTEM SET shared_buffers = '256MB';
```

#### Redis Optimization
```bash
# Monitor Redis performance
kubectl exec -it redis-0 -n phishnet -- redis-cli monitor

# Check memory usage
kubectl exec -it redis-0 -n phishnet -- redis-cli info memory
```

## 🔧 Configuration Reference

### Environment Variables

#### Required (Production)
- `POSTGRES_PASSWORD`: Database password
- `REDIS_PASSWORD`: Redis password
- `SECRET_KEY`: Application secret key (32+ chars)
- `ENCRYPTION_KEY`: Data encryption key (32 chars)

#### Gmail Integration
- `GMAIL_CLIENT_ID`: OAuth client ID
- `GMAIL_CLIENT_SECRET`: OAuth client secret
- `GMAIL_REDIRECT_URI`: OAuth redirect URI

#### External APIs
- `VIRUSTOTAL_API_KEY`: VirusTotal API key
- `ABUSEIPDB_API_KEY`: AbuseIPDB API key
- `GEMINI_API_KEY`: Google Gemini API key

#### Optional
- `LOG_LEVEL`: Logging level (DEBUG, INFO, WARNING, ERROR)
- `WORKER_CONCURRENCY`: Worker process count
- `BASE_URL`: Application base URL
- `RATE_LIMIT_PER_MINUTE`: API rate limiting

### Resource Requirements

#### Minimum (Development)
- CPU: 2 cores
- Memory: 4GB RAM
- Storage: 20GB

#### Recommended (Production)
- CPU: 8 cores
- Memory: 16GB RAM
- Storage: 100GB SSD
- Network: 1Gbps

#### High Availability (Enterprise)
- Multiple availability zones
- Load balancer
- Shared storage
- Database clustering

## 📞 Support & Escalation

### Health Check Endpoints
- `/health` - Comprehensive health status
- `/health/liveness` - Pod liveness probe
- `/health/readiness` - Pod readiness probe
- `/health/startup` - Startup probe
- `/metrics` - Prometheus metrics

### Monitoring Dashboards
- **System Overview**: CPU, memory, disk usage
- **Application Metrics**: Request rates, error rates, latency
- **Business Metrics**: Email processing, threat detection
- **External APIs**: Third-party service health

### Log Locations
- Application logs: `/app/logs/`
- Container logs: `kubectl logs <pod> -n phishnet`
- Audit logs: Database table `audit_logs`
- Access logs: Nginx/Ingress controller

### Escalation Procedures
1. **Level 1**: Check health endpoints and basic connectivity
2. **Level 2**: Review application logs and metrics
3. **Level 3**: Database and infrastructure investigation
4. **Level 4**: Contact development team or vendor support

---

For additional support, refer to the operational runbooks in `docs/runbooks/` or contact the platform team.
