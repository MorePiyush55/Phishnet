# PhishNet Sandbox Infrastructure - Complete Implementation

## Overview

This document describes the complete implementation of the PhishNet sandbox infrastructure, designed for secure analysis of potentially dangerous web pages. The system provides ephemeral container execution with comprehensive artifact capture, security isolation, and horizontal scaling capabilities.

## Architecture Components

### 1. Core Infrastructure

#### Secure Container Image (`Dockerfile.sandbox`)
- **Base**: Debian slim with minimal attack surface
- **Browser**: Headless Chromium with security hardening
- **Runtime**: Python 3.11 with Playwright automation
- **Security**: Non-root user, read-only filesystem, resource limits
- **Location**: `sandbox/Dockerfile.sandbox`

#### Sandbox Worker (`sandbox_worker.py`)
- **Purpose**: Core worker service for ephemeral container execution
- **Features**: 
  - Dual user-agent analysis (bot vs. real user) for cloaking detection
  - Screenshot capture and DOM snapshot collection
  - Network traffic monitoring with request/response logging
  - JavaScript console output capture
  - Security event detection and blocking
- **Security**: Network isolation, credential blocking, resource monitoring
- **Location**: `sandbox/sandbox_worker.py`

### 2. Job Queue System

#### Redis-based Job Queue (`job_queue.py`)
- **Architecture**: Distributed job queue with priority levels
- **Features**:
  - High/Normal/Low priority queues
  - Worker heartbeat tracking and timeout management
  - Job status tracking (pending, running, completed, failed)
  - Result aggregation and callback system
  - Queue statistics and monitoring
- **Scalability**: Horizontal worker scaling with load balancing
- **Location**: `sandbox/job_queue.py`

### 3. Artifact Storage System

#### Multi-Cloud Storage (`artifact_storage.py`)
- **Backends**: Amazon S3 and Google Cloud Storage support
- **Features**:
  - Automatic storage backend selection
  - Configurable retention policies (default: 7 days)
  - Artifact metadata tracking with checksums
  - Signed URL generation for secure access
  - Automatic cleanup of expired artifacts
- **Artifact Types**: Screenshots, DOM snapshots, network logs, console logs, analysis reports
- **Location**: `sandbox/artifact_storage.py`

### 4. Network Security

#### Firewall and Access Control (`network_security.py`)
- **Firewall Rules**: iptables-based blocking of private networks and credential endpoints
- **DNS Filtering**: Domain-based blocking of dangerous services
- **VPC Integration**: Security group rules for AWS/GCP deployment
- **Egress Control**: Whitelist-based outbound traffic control
- **Location**: `sandbox/network_security.py`

### 5. Monitoring and Logging

#### Comprehensive Monitoring (`monitoring.py`)
- **Metrics**: Prometheus metrics for job processing, resource usage, security events
- **Health Monitoring**: Container health checks and worker status tracking
- **Security Logging**: Structured logging of security events and violations
- **Alerting**: Configurable alerts for resource abuse and security incidents
- **Dashboard**: Real-time monitoring dashboard with worker status
- **Location**: `sandbox/monitoring.py`

### 6. Orchestration

#### Threat Orchestrator (`orchestrator.py`)
- **API**: RESTful API for job submission and result retrieval
- **Integration**: Seamless integration with existing threat analysis pipeline
- **Bulk Processing**: Support for batch URL analysis
- **Result Management**: Job tracking, status monitoring, and cleanup
- **Location**: `sandbox/orchestrator.py`

## Deployment Options

### 1. Docker Compose (Development/Small Scale)

```bash
# Start complete infrastructure
cd sandbox/
docker-compose -f docker-compose-updated.yml up -d

# Scale workers
docker-compose -f docker-compose-updated.yml up -d --scale sandbox-worker-1=3
```

**Services**:
- Redis (job queue)
- Orchestrator API (port 8000)
- 2x Sandbox Workers (scalable)
- Prometheus (monitoring, port 9000)
- Grafana (visualization, port 3000)
- Fluentd (log aggregation)

### 2. Kubernetes (Production Scale)

```bash
# Deploy infrastructure
kubectl apply -f sandbox/k8s/sandbox-infrastructure.yaml

# Scale workers
kubectl scale deployment sandbox-workers --replicas=10
```

**Features**:
- Namespace isolation
- Network policies for traffic control
- Pod security policies and constraints
- Horizontal Pod Autoscaler (HPA)
- Persistent storage for artifacts

## API Usage

### Submit URL for Analysis

```bash
curl -X POST http://localhost:8000/api/v1/analyze \
  -H "Content-Type: application/json" \
  -d '{"url": "https://suspicious-site.com", "priority": "high"}'
```

### Check Job Status

```bash
curl http://localhost:8000/api/v1/jobs/{job_id}/status
```

### Get Analysis Results

```bash
curl http://localhost:8000/api/v1/jobs/{job_id}/result
```

### Get Analysis Summary with Artifact URLs

```bash
curl http://localhost:8000/api/v1/jobs/{job_id}/summary
```

## Security Features

### Container Security
- **Non-root execution**: All processes run as unprivileged user
- **Read-only filesystem**: Prevents persistent malware installation
- **Resource limits**: CPU, memory, and I/O constraints
- **Seccomp profiles**: System call filtering
- **Network isolation**: Controlled egress with firewall rules

### Credential Protection
- **Metadata blocking**: AWS/GCP/Azure metadata services blocked
- **Private network blocking**: RFC 1918 networks inaccessible
- **Domain blacklisting**: Email, SSO, and cloud storage providers blocked
- **Credential endpoint detection**: Automatic blocking of authentication URLs

### Monitoring and Alerting
- **Security event logging**: Real-time detection of suspicious activity
- **Resource abuse detection**: Alerts for excessive CPU/memory usage
- **Container escape monitoring**: Detection of privilege escalation attempts
- **Network violation tracking**: Logging of blocked network requests

## Configuration

### Environment Variables

```bash
# Storage Configuration
ARTIFACTS_BUCKET=phishnet-sandbox-artifacts
ARTIFACTS_RETENTION_DAYS=7
AWS_ACCESS_KEY_ID=your_aws_key
AWS_SECRET_ACCESS_KEY=your_aws_secret
GOOGLE_APPLICATION_CREDENTIALS=/path/to/gcs-key.json

# Redis Configuration
REDIS_URL=redis://localhost:6379/0

# Monitoring Configuration
PROMETHEUS_PORT=9090
DASHBOARD_PORT=8080
ALERT_WEBHOOK_URL=https://your-webhook-url

# Security Configuration
SETUP_NETWORK_SECURITY=true
```

### File Structure

```
sandbox/
├── Dockerfile.sandbox              # Secure container image
├── requirements-sandbox.txt        # Python dependencies
├── sandbox_worker.py              # Core worker service
├── job_queue.py                   # Redis job queue system
├── artifact_storage.py           # Multi-cloud storage
├── network_security.py           # Firewall and access control
├── monitoring.py                 # Monitoring and logging
├── orchestrator.py              # Threat orchestrator API
├── docker-compose-updated.yml   # Complete infrastructure
└── k8s/
    └── sandbox-infrastructure.yaml # Kubernetes deployment
```

## Scaling and Performance

### Horizontal Scaling
- **Worker Scaling**: Add more worker containers for increased throughput
- **Queue Partitioning**: Separate queues for different priority levels
- **Load Balancing**: Automatic job distribution across available workers

### Performance Metrics
- **Job Throughput**: Monitor jobs per second processing rate
- **Analysis Duration**: Track average time for URL analysis
- **Queue Depth**: Monitor pending job counts
- **Resource Utilization**: CPU, memory, and network usage per worker

### Capacity Planning
- **Worker Sizing**: 1 CPU, 1GB RAM per worker recommended
- **Storage Requirements**: 100MB average per analysis result
- **Network Bandwidth**: 10 Mbps per worker for page loading
- **Redis Memory**: 256MB base + 1MB per 1000 queued jobs

## Integration Examples

### Python Integration

```python
import asyncio
from orchestrator import ThreatOrchestrator

async def analyze_urls():
    orchestrator = ThreatOrchestrator()
    
    # Submit URL for analysis
    job_id = await orchestrator.analyze_url("https://suspicious-site.com")
    
    # Wait for completion
    result = await orchestrator.get_analysis_result(job_id)
    
    # Get artifact URLs
    summary = await orchestrator.get_analysis_summary(job_id)
    print(f"Screenshots: {summary['artifacts']['screenshot']}")
```

### REST API Integration

```javascript
// Submit URL
const response = await fetch('/api/v1/analyze', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({url: 'https://suspicious-site.com'})
});
const {job_id} = await response.json();

// Poll for completion
const checkStatus = async () => {
    const status = await fetch(`/api/v1/jobs/${job_id}/status`);
    const {status: jobStatus} = await status.json();
    return jobStatus === 'completed';
};
```

## Troubleshooting

### Common Issues

1. **Worker Not Starting**
   - Check Docker daemon status
   - Verify Redis connectivity
   - Review container logs: `docker logs phishnet-sandbox-worker-1`

2. **Jobs Stuck in Queue**
   - Verify worker health: `curl http://localhost:8080/workers`
   - Check Redis queue: `redis-cli llen sandbox_queue`
   - Review worker heartbeats

3. **Artifact Storage Failures**
   - Verify AWS/GCS credentials
   - Check bucket permissions
   - Review storage backend logs

4. **Network Security Issues**
   - Verify firewall rules: `iptables -L`
   - Check DNS resolution
   - Review security event logs

### Monitoring Endpoints

- **Queue Statistics**: `http://localhost:8000/api/v1/queue/stats`
- **Worker Health**: `http://localhost:8080/workers`
- **Prometheus Metrics**: `http://localhost:9090/metrics`
- **System Health**: `http://localhost:8080/health`

## Security Considerations

### Production Deployment
1. **Certificate Management**: Use TLS certificates for all API endpoints
2. **Authentication**: Implement API key or OAuth authentication
3. **Network Segmentation**: Deploy workers in isolated network segments
4. **Secret Management**: Use vault systems for credential storage
5. **Regular Updates**: Keep container images and dependencies updated

### Compliance
- **Data Retention**: Configurable artifact retention for compliance requirements
- **Audit Logging**: Complete audit trail of all analysis activities
- **Access Control**: Role-based access to analysis results
- **Data Encryption**: Encryption at rest and in transit for artifacts

## Maintenance

### Regular Tasks
1. **Artifact Cleanup**: Automated cleanup of expired artifacts
2. **Log Rotation**: Regular rotation of container logs
3. **Health Monitoring**: Continuous monitoring of worker health
4. **Security Updates**: Regular updates of container images

### Backup and Recovery
1. **Redis Backup**: Regular backup of job queue state
2. **Artifact Backup**: Cross-region replication of critical artifacts
3. **Configuration Backup**: Version control for all configuration files
4. **Disaster Recovery**: Automated failover procedures

This completes the comprehensive PhishNet sandbox infrastructure implementation, providing a production-ready system for secure web page analysis with enterprise-grade security, monitoring, and scalability features.
