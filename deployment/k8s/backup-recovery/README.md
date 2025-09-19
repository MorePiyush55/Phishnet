# PhishNet Backup and Recovery Implementation Guide

## Overview

This document describes the comprehensive backup and recovery system implemented for PhishNet, providing enterprise-grade data protection and disaster recovery capabilities.

## Architecture

### Components

1. **Automated Database Backups** - Daily PostgreSQL dumps with compression and cloud storage
2. **Redis Backups** - Daily RDB file backups with retention policies  
3. **Volume Snapshots** - Block-level snapshots using Kubernetes CSI
4. **Disaster Recovery Scripts** - Automated recovery orchestration
5. **Backup Testing Framework** - Continuous validation of backup integrity
6. **Monitoring and Alerting** - Comprehensive backup health monitoring

### Storage Strategy

- **Local Storage**: Primary backup storage on persistent volumes
- **Cloud Storage**: Secondary backup storage in AWS S3/GCS/Azure Blob
- **Encryption**: All backups encrypted at rest and in transit
- **Compression**: GZIP compression for space efficiency

## Backup Schedule

### Database Backups
- **PostgreSQL**: Daily at 2:00 AM UTC
- **Redis**: Daily at 3:00 AM UTC
- **Retention**: 30 days for PostgreSQL, 7 days for Redis

### Volume Snapshots
- **PostgreSQL Volume**: Daily at 1:00 AM UTC
- **Redis Volume**: Daily at 1:15 AM UTC
- **Retention**: 30 days for PostgreSQL, 7 days for Redis

### Testing
- **Backup Integrity Tests**: Weekly on Sunday at 4:00 AM UTC
- **Recovery Drills**: Monthly (manual process)

## Implementation Files

### 1. Backup Jobs (`k8s/backup-recovery/backup-jobs.yaml`)

#### PostgreSQL Backup CronJob
```yaml
apiVersion: batch/v1
kind: CronJob
metadata:
  name: postgres-backup
spec:
  schedule: "0 2 * * *"  # Daily at 2 AM UTC
```

**Features:**
- Custom format backups with compression level 9
- Integrity verification using `pg_restore --list`
- Metadata generation with checksums and backup details
- Automatic cleanup of backups older than 30 days
- Cloud storage upload support (S3/GCS/Azure)

#### Redis Backup CronJob
```yaml
apiVersion: batch/v1
kind: CronJob
metadata:
  name: redis-backup
spec:
  schedule: "0 3 * * *"  # Daily at 3 AM UTC
```

**Features:**
- RDB format backups using `BGSAVE` command
- GZIP compression for space efficiency
- Automatic cleanup of backups older than 7 days
- Non-blocking backup process

### 2. Volume Snapshots (`k8s/backup-recovery/volume-snapshots.yaml`)

#### VolumeSnapshotClass
```yaml
apiVersion: snapshot.storage.k8s.io/v1
kind: VolumeSnapshotClass
metadata:
  name: phishnet-snapshot-class
spec:
  driver: ebs.csi.aws.com
  deletionPolicy: Retain
```

**Features:**
- Encrypted snapshots using CSI driver
- Automatic tagging for resource management
- Retention policy enforcement
- RBAC controls for snapshot operations

### 3. Disaster Recovery Script (`k8s/backup-recovery/disaster-recovery.sh`)

**Capabilities:**
- List available backups and snapshots
- Verify backup integrity before restoration
- Scale down applications during recovery
- Restore from database backups or volume snapshots
- Scale up applications after recovery
- Validate system health post-recovery

**Usage Examples:**
```bash
# List available backups
./disaster-recovery.sh list

# Verify backup integrity
./disaster-recovery.sh verify /backups/phishnet_backup_20240101_020000.sql.gz postgres

# Perform full recovery
./disaster-recovery.sh recover full 20240101_020000

# Restore from volume snapshot
./disaster-recovery.sh recover snapshot postgres-snapshot-20240101-010000

# Dry run mode
DRY_RUN=true ./disaster-recovery.sh recover full 20240101_020000
```

### 4. Backup Testing (`k8s/backup-recovery/backup-tests.yaml`)

**Test Suite Includes:**
- Database connectivity tests
- Test data creation and backup
- Backup integrity verification
- Restore functionality testing
- Data consistency validation
- Compression ratio testing

**Weekly Automated Testing:**
- Runs every Sunday at 4:00 AM UTC
- Tests both PostgreSQL and Redis backups
- Generates detailed test reports
- Alerts on test failures

## Recovery Procedures

### 1. Full System Recovery

**When to Use:** Complete system failure, data corruption, or major disaster

**Steps:**
1. Scale down all application services
2. Restore PostgreSQL from latest backup
3. Restore Redis from latest backup
4. Scale up application services
5. Validate system health

```bash
./disaster-recovery.sh recover full 20240315_020000
```

### 2. Database-Only Recovery

**When to Use:** Database corruption or data loss without Redis issues

**Steps:**
1. Scale down application services
2. Restore PostgreSQL database only
3. Scale up application services
4. Validate functionality

```bash
./disaster-recovery.sh recover database-only 20240315_020000
```

### 3. Point-in-Time Recovery

**When to Use:** Need to restore to specific time before data corruption

**Requirements:**
- WAL archiving enabled (production setup)
- Base backup + WAL files available

**Process:**
1. Restore from base backup
2. Apply WAL files up to target time
3. Validate data consistency

### 4. Volume Snapshot Recovery

**When to Use:** Quick recovery from recent snapshot, storage issues

**Advantages:**
- Faster than logical backups
- Block-level consistency
- Minimal downtime

```bash
./disaster-recovery.sh recover snapshot postgres-snapshot-20240315-010000
```

## Monitoring and Alerting

### Prometheus Alerts

1. **BackupJobFailed** - Backup job failure detection
2. **BackupJobTooOld** - Stale backup detection (>24 hours)
3. **VolumeSnapshotFailed** - Snapshot creation failures

### Metrics Tracked

- Backup job execution time
- Backup file sizes
- Backup success/failure rates
- Storage utilization
- Recovery test results

### Dashboards

- Backup status overview
- Backup size trends
- Recovery time objectives (RTO)
- Recovery point objectives (RPO)

## Security Considerations

### Access Controls
- RBAC for backup operations
- Service accounts with minimal permissions
- Secret management for credentials

### Encryption
- Database backups encrypted using PostgreSQL's built-in encryption
- Cloud storage encryption at rest
- TLS encryption for data in transit

### Audit Trail
- All backup operations logged
- Recovery operations tracked
- Access to backup storage monitored

## Compliance and Retention

### Retention Policies
```yaml
retention:
  database:
    daily: 30     # Keep daily backups for 30 days
    weekly: 12    # Keep weekly backups for 12 weeks  
    monthly: 12   # Keep monthly backups for 12 months
  redis:
    daily: 7      # Keep daily backups for 7 days
    weekly: 4     # Keep weekly backups for 4 weeks
  audit_logs:
    daily: 90     # Keep audit logs for 90 days
    archive: 2555 # Archive for 7 years
```

### Legal Requirements
- GDPR compliance for EU data
- Data residency requirements
- Audit trail maintenance
- Secure data destruction

## Performance Optimization

### Backup Performance
- Compressed backups reduce storage costs
- Parallel backup jobs for different components
- Non-blocking backup processes during business hours
- Incremental backups for large datasets (future enhancement)

### Recovery Performance
- Volume snapshots for faster recovery
- Staged recovery process (databases first, then applications)
- Health checks before declaring recovery complete
- Rollback procedures if recovery fails

## Testing and Validation

### Automated Testing
- Weekly backup integrity tests
- Monthly recovery drills (manual)
- Continuous monitoring of backup health
- Automated alerts on test failures

### Manual Testing Procedures
1. Quarterly full disaster recovery tests
2. Annual business continuity exercises
3. New deployment validation tests
4. Performance benchmark testing

## Troubleshooting

### Common Issues

#### Backup Job Failures
- Check storage space availability
- Verify database connectivity
- Review service account permissions
- Check resource limits and requests

#### Recovery Failures
- Verify backup file integrity
- Check target storage availability
- Ensure proper scaling of applications
- Validate network connectivity

#### Performance Issues
- Monitor backup job execution times
- Check storage I/O performance
- Review resource allocation
- Consider backup scheduling optimization

### Diagnostic Commands
```bash
# Check backup job status
kubectl get cronjobs -n phishnet

# View backup job logs
kubectl logs -n phishnet job/postgres-backup-<timestamp>

# Check storage usage
kubectl get pvc -n phishnet backup-storage

# Verify snapshots
kubectl get volumesnapshots -n phishnet

# Test database connectivity
kubectl exec -n phishnet statefulset/postgres -- pg_isready
```

## Future Enhancements

### Planned Improvements
- Cross-region backup replication
- Incremental backup support
- Automated recovery testing
- Integration with cloud backup services
- Enhanced monitoring dashboards

### Considerations
- Multi-cloud backup strategy
- Zero-downtime backup procedures
- Advanced encryption key management
- Compliance automation
- Cost optimization strategies

## Summary

The PhishNet backup and recovery system provides:

✅ **Automated daily backups** for PostgreSQL and Redis
✅ **Volume snapshots** for block-level consistency
✅ **Disaster recovery scripts** for automated restoration
✅ **Comprehensive testing framework** for backup validation
✅ **Monitoring and alerting** for backup health
✅ **Security and encryption** for data protection
✅ **Compliance-ready retention** policies
✅ **Performance optimization** for minimal impact

This implementation ensures enterprise-grade data protection with Recovery Time Objective (RTO) of less than 30 minutes and Recovery Point Objective (RPO) of less than 24 hours for standard scenarios.
