# Sandbox Integration Deployment Guide

This guide covers the deployment and configuration of the sandbox-integrated threat orchestrator for PhishNet.

## Overview

The sandbox integration adds comprehensive URL analysis capabilities to PhishNet's threat detection system. It includes:

- **Cloaking Detection**: Identifies sites that show different content to bots vs. real users
- **Security Isolation**: Runs URL analysis in isolated browser environments
- **Artifact Collection**: Captures screenshots, DOM snapshots, and network logs
- **Enhanced Threat Scoring**: Combines standard threat intelligence with sandbox findings

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                    PhishNet API Layer                                │
├─────────────────────────────────────────────────────────────────────┤
│  Enhanced Threat Orchestrator                                       │
│  ├── Standard Services (VirusTotal, AbuseIPDB, etc.)                │
│  └── Sandbox Integration Layer                                      │
│      ├── Job Queuing (Redis)                                        │
│      ├── Worker Management                                          │
│      └── Result Aggregation                                         │
├─────────────────────────────────────────────────────────────────────┤
│  Sandbox Infrastructure                                             │
│  ├── Security Profiles (seccomp, AppArmor)                         │
│  ├── Browser Workers (Playwright + Chrome)                         │
│  ├── Artifact Storage                                               │
│  └── Monitoring & Logging                                           │
└─────────────────────────────────────────────────────────────────────┘
```

## Prerequisites

### System Requirements

- **Operating System**: Linux (Ubuntu 20.04+ recommended)
- **Memory**: Minimum 8GB RAM, 16GB+ recommended
- **Storage**: 50GB+ available disk space
- **CPU**: 4+ cores recommended
- **Docker**: Version 20.10+
- **Docker Compose**: Version 2.0+

### Network Requirements

- Outbound internet access for URL analysis
- Ports 8000 (API), 6379 (Redis), 3000 (Grafana), 9090 (Prometheus)

## Installation

### 1. Environment Setup

```bash
# Clone the repository
git clone <repository-url>
cd PhishNet

# Set up environment variables
cp env.example .env

# Edit .env with your configuration
nano .env
```

### 2. Required Environment Variables

Add the following to your `.env` file:

```bash
# Sandbox Configuration
SANDBOX_ENABLED=true
SANDBOX_TIMEOUT=300
MAX_SANDBOX_URLS=5
SANDBOX_REDIS_DB=2
SANDBOX_WORKER_COUNT=2
SANDBOX_JOB_RETRY_COUNT=2
SANDBOX_STORAGE_RETENTION_DAYS=7

# Security Hardening
SANDBOX_SECCOMP_ENABLED=true
SANDBOX_APPARMOR_ENABLED=true
SANDBOX_NETWORK_ISOLATION=true
SANDBOX_MAX_MEMORY=512m
SANDBOX_MAX_CPU=0.5

# Redis Configuration
REDIS_URL=redis://redis:6379/0

# API Keys (optional but recommended)
VIRUSTOTAL_API_KEY=your_virustotal_key
ABUSEIPDB_API_KEY=your_abuseipdb_key
```

### 3. Security Profile Installation

Install security profiles on the host system:

```bash
# Install AppArmor profile
sudo cp sandbox/apparmor-profile /etc/apparmor.d/phishnet-sandbox
sudo apparmor_parser -r /etc/apparmor.d/phishnet-sandbox

# Verify AppArmor profile is loaded
sudo aa-status | grep phishnet-sandbox
```

### 4. Docker Deployment

```bash
# Build and start all services
docker-compose up -d

# Verify services are running
docker-compose ps

# Check logs
docker-compose logs -f sandbox-worker
docker-compose logs -f phishnet-api
```

### 5. Database Migration

```bash
# Run database migrations
docker-compose exec phishnet-api alembic upgrade head

# Verify database schema
docker-compose exec phishnet-api python -c "from app.core.database import get_db; print('Database connection successful')"
```

## Configuration

### Sandbox Workers

Configure sandbox workers based on your system resources:

```yaml
# docker-compose.yml
sandbox-worker:
  image: phishnet/sandbox-worker
  environment:
    - WORKER_CONCURRENCY=2  # Adjust based on CPU/memory
    - BROWSER_INSTANCES=1   # Browsers per worker
    - ANALYSIS_TIMEOUT=300  # Per-job timeout
  deploy:
    replicas: 2  # Number of worker containers
    resources:
      limits:
        memory: 512M
        cpus: '0.5'
```

### Monitoring Setup

The sandbox includes comprehensive monitoring:

```bash
# Access monitoring dashboards
http://localhost:3000  # Grafana (admin/admin)
http://localhost:9090  # Prometheus

# Import dashboard configurations
docker-compose exec grafana grafana-cli plugins install grafana-piechart-panel
```

### Log Configuration

Structured logging is configured in `sandbox/setup_logging.py`:

```python
# Key log categories
- security_events: Security violations and threats
- analysis_results: URL analysis outcomes
- system_health: Performance and resource usage
- audit_trail: User actions and system changes
```

## API Usage

### Basic Threat Analysis

```bash
curl -X POST "http://localhost:8000/api/v1/threat-analysis/analyze" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "urls_to_analyze": ["https://suspicious-site.com"],
    "analysis_depth": "comprehensive",
    "priority": "high",
    "enable_sandbox": true
  }'
```

### Email Analysis

```bash
curl -X POST "http://localhost:8000/api/v1/threat-analysis/analyze-email/123" \
  -H "Authorization: Bearer $TOKEN" \
  -d "priority=high&enable_sandbox=true"
```

### Sandbox Results

```bash
curl -X GET "http://localhost:8000/api/v1/threat-analysis/sandbox-results/$JOB_ID" \
  -H "Authorization: Bearer $TOKEN"
```

## Response Examples

### Enhanced Threat Analysis Response

```json
{
  "scan_request_id": "uuid-here",
  "threat_level": "high",
  "threat_score": 0.85,
  "confidence": 0.92,
  "sandbox_analysis_count": 2,
  "cloaking_detected": true,
  "malicious_urls": ["https://malicious-site.com"],
  "phishing_indicators": [
    "Cloaking detected: https://cloaking-site.com",
    "Suspicious redirect chain detected"
  ],
  "sandbox_results": {
    "https://suspicious-site.com": {
      "job_id": "job-uuid",
      "cloaking_detected": true,
      "threat_score": 0.8,
      "security_findings": [
        "Multiple suspicious redirects",
        "Blocked malicious request"
      ],
      "screenshots": [...],
      "archive_url": "https://storage/artifacts/job-uuid.zip"
    }
  },
  "recommendations": [
    "CRITICAL: Cloaking behavior detected. Block this URL.",
    "Review redirect chains for potential phishing."
  ]
}
```

### Sandbox Analysis Result

```json
{
  "job_id": "sandbox-job-uuid",
  "target_url": "https://suspicious-site.com",
  "cloaking_detected": true,
  "threat_score": 0.8,
  "security_findings": [
    "Different content served to bot vs real user",
    "Suspicious JavaScript execution"
  ],
  "screenshots": [
    {
      "user_type": "bot",
      "url": "https://storage/screenshots/bot-view.png",
      "timestamp": "2024-01-15T10:30:00Z"
    },
    {
      "user_type": "real",
      "url": "https://storage/screenshots/real-view.png", 
      "timestamp": "2024-01-15T10:30:05Z"
    }
  ],
  "cloaking_evidence": [
    "Title differs: 'Legitimate Site' vs 'Login Now'",
    "Different form elements detected"
  ]
}
```

## Monitoring and Maintenance

### Health Checks

```bash
# Check overall system health
curl http://localhost:8000/api/v1/threat-analysis/health

# Monitor sandbox worker status
curl http://localhost:8000/api/v1/system/health
```

### Performance Monitoring

Key metrics to monitor:

- **Analysis Throughput**: URLs processed per minute
- **Cloaking Detection Rate**: Percentage of URLs with cloaking
- **Resource Usage**: CPU, memory, disk usage per worker
- **Queue Length**: Pending jobs in Redis queue
- **Error Rates**: Failed analyses and timeouts

### Log Analysis

```bash
# View security events
docker-compose logs sandbox-worker | grep "SECURITY_EVENT"

# Monitor cloaking detection
docker-compose logs sandbox-worker | grep "cloaking_detected.*true"

# Check for errors
docker-compose logs --tail=100 | grep ERROR
```

### Maintenance Tasks

```bash
# Clean up old artifacts (run daily)
docker-compose exec sandbox-worker python scripts/cleanup_artifacts.py

# Restart sandbox workers (if needed)
docker-compose restart sandbox-worker

# Update security profiles
sudo apparmor_parser -r /etc/apparmor.d/phishnet-sandbox
```

## Troubleshooting

### Common Issues

1. **Sandbox Workers Not Starting**
   ```bash
   # Check Docker resources
   docker system df
   docker system prune
   
   # Verify seccomp profile
   docker run --security-opt seccomp=sandbox/seccomp-profile.json alpine echo "test"
   ```

2. **High Resource Usage**
   ```bash
   # Scale down workers
   docker-compose up -d --scale sandbox-worker=1
   
   # Adjust worker concurrency
   # Edit docker-compose.yml WORKER_CONCURRENCY
   ```

3. **Cloaking Detection Issues**
   ```bash
   # Check browser profiles
   docker-compose exec sandbox-worker python -c "from browser_profiles import test_profiles; test_profiles()"
   
   # Verify user agent rotation
   docker-compose logs sandbox-worker | grep "user_agent"
   ```

4. **Network Connectivity Issues**
   ```bash
   # Test outbound connectivity
   docker-compose exec sandbox-worker curl -I https://google.com
   
   # Check DNS resolution
   docker-compose exec sandbox-worker nslookup suspicious-site.com
   ```

### Debug Mode

Enable debug mode for detailed logging:

```bash
# Set environment variable
export SANDBOX_DEBUG=true

# Restart services
docker-compose restart

# View debug logs
docker-compose logs -f | grep DEBUG
```

## Security Considerations

### Container Security

- **Seccomp Profiles**: Restrict system calls to prevent container escape
- **AppArmor**: Limit file system access and capabilities
- **Network Isolation**: Prevent lateral movement between containers
- **Resource Limits**: Prevent resource exhaustion attacks

### Data Protection

- **Artifact Encryption**: Sandbox artifacts encrypted at rest
- **Secure Deletion**: Automatic cleanup after retention period
- **Access Controls**: Role-based access to sandbox results
- **Audit Logging**: All access and modifications logged

### Network Security

- **Egress Filtering**: Only necessary outbound connections allowed
- **TLS Enforcement**: All API communications encrypted
- **Rate Limiting**: Prevent abuse and DoS attacks
- **IP Whitelisting**: Restrict API access to known networks

## Performance Tuning

### Scaling Guidelines

- **Low Volume** (< 100 URLs/day): 1-2 workers, 2GB RAM
- **Medium Volume** (100-1000 URLs/day): 2-4 workers, 4GB RAM
- **High Volume** (1000+ URLs/day): 4+ workers, 8GB+ RAM

### Optimization Tips

1. **Worker Tuning**: Adjust concurrency based on CPU cores
2. **Browser Reuse**: Enable browser instance reuse for better performance
3. **Artifact Compression**: Use compression for large screenshots
4. **Caching**: Implement result caching for repeated URLs
5. **Priority Queues**: Process high-priority requests first

## Backup and Recovery

### Backup Strategy

```bash
# Backup configuration
tar -czf phishnet-config-backup.tar.gz .env docker-compose.yml sandbox/

# Backup Redis data
docker-compose exec redis redis-cli BGSAVE

# Backup artifacts
tar -czf artifacts-backup.tar.gz sandbox/storage/
```

### Recovery Procedures

```bash
# Restore configuration
tar -xzf phishnet-config-backup.tar.gz

# Restore Redis data
docker-compose stop redis
# Copy backup to Redis volume
docker-compose start redis

# Restore artifacts
tar -xzf artifacts-backup.tar.gz
```

## Support and Updates

### Getting Help

- **Documentation**: Check this guide and API documentation
- **Logs**: Review system logs for error details
- **Health Endpoints**: Use health check APIs for status
- **Monitoring**: Check Grafana dashboards for insights

### Updates

```bash
# Update to latest version
git pull origin main
docker-compose pull
docker-compose up -d

# Run any necessary migrations
docker-compose exec phishnet-api alembic upgrade head
```

For additional support or questions, please refer to the project documentation or contact the development team.
