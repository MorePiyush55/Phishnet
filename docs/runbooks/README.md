# PhishNet Operational Runbooks

This directory contains comprehensive operational runbooks for managing PhishNet in production environments.

## Table of Contents

### Incident Response Runbooks
- [Gmail API Quota Exhaustion](gmail-api-quota-exhaustion.md)
- [Sandbox Compromise](sandbox-compromise.md)
- [Data Leak Response](data-leak-response.md)
- [High Volume Attack Response](high-volume-attack-response.md)

### Operational Procedures
- [Standard Operating Procedures](standard-operating-procedures.md)
- [Deployment Procedures](deployment-procedures.md)
- [Backup and Recovery](backup-recovery-procedures.md)
- [Monitoring and Alerting](monitoring-alerting-procedures.md)

### Troubleshooting Guides
- [Database Performance Issues](troubleshooting-database.md)
- [Redis Cache Issues](troubleshooting-redis.md)
- [Worker Queue Backlog](troubleshooting-workers.md)
- [Network and Connectivity](troubleshooting-network.md)

### Maintenance Procedures
- [Scheduled Maintenance](scheduled-maintenance.md)
- [Security Updates](security-updates.md)
- [Capacity Planning](capacity-planning.md)
- [Log Management](log-management.md)

## Quick Reference

### Emergency Contacts
- **On-Call Engineer**: [Your team's on-call rotation]
- **Security Team**: security@yourcompany.com
- **DevOps Team**: devops@yourcompany.com
- **Product Owner**: product@yourcompany.com

### Critical Services Health Check
```bash
# Quick health check commands
kubectl get pods -n phishnet
kubectl get services -n phishnet
kubectl top nodes
kubectl top pods -n phishnet
```

### Emergency Procedures
1. **System Down**: Follow [Standard Operating Procedures](standard-operating-procedures.md#system-down)
2. **Security Incident**: Follow [Data Leak Response](data-leak-response.md)
3. **Performance Issues**: Follow [Database Performance Issues](troubleshooting-database.md)
4. **Capacity Issues**: Follow [Capacity Planning](capacity-planning.md)

## Using These Runbooks

Each runbook follows a standardized format:
- **Severity Level**: Critical, High, Medium, Low
- **Detection**: How to identify the issue
- **Immediate Actions**: First steps to take
- **Investigation**: How to analyze the problem
- **Resolution**: Step-by-step fix procedures
- **Prevention**: How to prevent recurrence
- **Escalation**: When and how to escalate

## Runbook Maintenance

These runbooks should be:
- Reviewed quarterly
- Updated after each incident
- Tested during disaster recovery drills
- Kept up-to-date with system changes
