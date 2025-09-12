# Sandbox Compromise Incident Response

## Overview
This runbook provides procedures for handling potential sandbox environment compromise in PhishNet's malware analysis system.

## Incident Classification
- **Severity**: Critical (Security incident)
- **Impact**: Potential malware escape, system compromise
- **Type**: Security breach / containment failure

## Detection and Alerting

### Symptoms
- Unexpected network traffic from sandbox containers
- Sandbox containers attempting outbound connections
- Unusual process execution within sandboxes
- Resource exhaustion on sandbox hosts
- Security tool alerts from sandbox monitoring

### Monitoring Alerts
```yaml
# Prometheus Alerts
- alert: SandboxOutboundConnection
  expr: increase(sandbox_outbound_connections_total[5m]) > 0
  for: 1m
  labels:
    severity: critical
    service: sandbox
  annotations:
    summary: "Sandbox attempting outbound connections"
    description: "Sandbox {{ $labels.sandbox_id }} attempting {{ $value }} outbound connections"

- alert: SandboxResourceExhaustion
  expr: sandbox_cpu_usage > 90 or sandbox_memory_usage > 90
  for: 2m
  labels:
    severity: high
    service: sandbox
  annotations:
    summary: "Sandbox resource exhaustion detected"

- alert: SandboxAnomalousProcess
  expr: increase(sandbox_suspicious_processes_total[5m]) > 0
  for: 0m
  labels:
    severity: critical
    service: sandbox
  annotations:
    summary: "Suspicious process detected in sandbox"
```

### Key Indicators
- Network connections outside allowed ranges
- Process execution outside expected patterns
- File system modifications in protected areas
- Privilege escalation attempts
- Container escape attempts

## Immediate Response (0-5 minutes)

### 1. EMERGENCY: Isolate Affected Sandboxes
```bash
# IMMEDIATE ACTION - Isolate sandbox network
kubectl patch networkpolicy sandbox-isolation -n phishnet -p '{"spec":{"policyTypes":["Ingress","Egress"],"egress":[]}}'

# Stop all sandbox containers immediately
kubectl scale deployment phishnet-sandbox --replicas=0 -n phishnet

# Verify sandboxes are stopped
kubectl get pods -n phishnet -l app=phishnet-sandbox
```

### 2. Alert Security Team
```bash
# Send immediate security alert
curl -X POST https://security-alerts.company.com/api/incidents \
  -H "Content-Type: application/json" \
  -d '{
    "severity": "CRITICAL",
    "type": "sandbox_compromise",
    "timestamp": "'$(date -u +%Y-%m-%dT%H:%M:%SZ)'",
    "description": "Potential sandbox compromise detected in PhishNet",
    "affected_systems": ["phishnet-sandbox"],
    "immediate_actions": ["sandbox_isolated", "containers_stopped"]
  }'
```

### 3. Capture Evidence
```bash
# Capture sandbox logs before they rotate
kubectl logs -n phishnet deployment/phishnet-sandbox --all-containers=true > /tmp/sandbox-incident-logs-$(date +%s).log

# Capture network policy state
kubectl get networkpolicies -n phishnet -o yaml > /tmp/network-policies-$(date +%s).yaml

# Capture pod states
kubectl get pods -n phishnet -o wide > /tmp/pod-states-$(date +%s).txt
```

## Investigation (5-30 minutes)

### 1. Analyze Sandbox Activity
```bash
# Review recent sandbox executions
kubectl exec -n phishnet deployment/phishnet-api -- curl -s "http://localhost:8000/api/v1/sandbox/recent-activity"

# Check for unusual file analysis patterns
kubectl logs -n phishnet deployment/phishnet-sandbox --since=1h | grep -E "(error|warning|suspicious|outbound|connection)" | head -50

# Review security monitoring logs
kubectl logs -n phishnet deployment/falco-security --since=1h | grep sandbox
```

### 2. Network Traffic Analysis
```bash
# Check for outbound connections (if monitoring available)
kubectl exec -n phishnet deployment/network-monitor -- netstat -tuln | grep ESTABLISHED

# Review DNS queries from sandbox
kubectl logs -n phishnet deployment/dns-monitor --since=1h | grep sandbox

# Check for data exfiltration patterns
kubectl exec -n phishnet deployment/phishnet-api -- curl -s "http://prometheus:9090/api/v1/query?query=increase(sandbox_data_transfer_bytes[1h])"
```

### 3. Host System Check
```bash
# Verify host system integrity
kubectl get nodes -o wide

# Check for container escape indicators
kubectl exec -n phishnet daemonset/security-monitor -- /opt/security/container-escape-check.sh

# Review host-level security logs
kubectl logs -n kube-system daemonset/security-agent --since=1h | grep -i escape
```

### 4. Malware Analysis
```bash
# Identify the specific file being analyzed when compromise occurred
INCIDENT_TIME=$(date -d '10 minutes ago' +%Y-%m-%d\ %H:%M:%S)
kubectl exec -n phishnet deployment/phishnet-api -- psql -h postgres -U phishnet_user -d phishnet -c "
  SELECT id, filename, submitted_at, analysis_status 
  FROM file_analysis 
  WHERE submitted_at >= '$INCIDENT_TIME' 
  ORDER BY submitted_at DESC 
  LIMIT 10;
"

# Get file hash for investigation
SUSPECT_FILE_ID="[from above query]"
kubectl exec -n phishnet deployment/phishnet-api -- psql -h postgres -U phishnet_user -d phishnet -c "
  SELECT file_hash, file_type, analysis_result 
  FROM file_analysis 
  WHERE id = '$SUSPECT_FILE_ID';
"
```

## Containment (30-60 minutes)

### 1. Complete Network Isolation
```bash
# Create strict network policy for sandbox namespace
cat << EOF | kubectl apply -f -
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: sandbox-complete-isolation
  namespace: phishnet
spec:
  podSelector:
    matchLabels:
      app: phishnet-sandbox
  policyTypes:
  - Ingress
  - Egress
  # No ingress or egress rules = complete isolation
EOF
```

### 2. Quarantine Suspicious Files
```bash
# Move suspicious files to quarantine
QUARANTINE_BUCKET="phishnet-quarantine-$(date +%s)"
aws s3 mb s3://$QUARANTINE_BUCKET

# List recent uploads that may be compromised
kubectl exec -n phishnet deployment/phishnet-api -- aws s3 ls s3://phishnet-uploads/ --recursive --human-readable | tail -20

# Move suspicious files to quarantine
SUSPECT_FILES="[list from investigation]"
for file in $SUSPECT_FILES; do
  aws s3 mv s3://phishnet-uploads/$file s3://$QUARANTINE_BUCKET/
done
```

### 3. Reset Sandbox Environment
```bash
# Delete all sandbox-related resources
kubectl delete pods -n phishnet -l app=phishnet-sandbox --force --grace-period=0

# Clear any persistent data
kubectl exec -n phishnet deployment/phishnet-api -- rm -rf /tmp/sandbox-*

# Reset sandbox images (pull fresh images)
kubectl delete pods -n phishnet -l app=phishnet-sandbox
docker system prune -f
```

### 4. Update Security Policies
```bash
# Temporarily disable sandbox analysis
kubectl patch configmap phishnet-api-config -n phishnet -p '{"data":{"SANDBOX_ENABLED":"false"}}'

# Restart API to pick up config change
kubectl rollout restart deployment/phishnet-api -n phishnet

# Update admission controller to block sandbox pods
cat << EOF | kubectl apply -f -
apiVersion: v1
kind: ConfigMap
metadata:
  name: admission-controller-config
  namespace: phishnet
data:
  deny-sandbox-pods: "true"
EOF
```

## Eradication (1-2 hours)

### 1. Forensic Analysis
```bash
# Create forensic snapshot of affected nodes
NODE_NAME="[affected node from investigation]"
aws ec2 create-snapshot --volume-id $(aws ec2 describe-instances --filters "Name=private-dns-name,Values=$NODE_NAME" --query 'Reservations[0].Instances[0].BlockDeviceMappings[0].Ebs.VolumeId' --output text) --description "PhishNet incident forensics $(date)"

# Preserve evidence
mkdir -p /tmp/incident-evidence-$(date +%s)
cp /tmp/sandbox-incident-logs-*.log /tmp/incident-evidence-*/
cp /tmp/network-policies-*.yaml /tmp/incident-evidence-*/
cp /tmp/pod-states-*.txt /tmp/incident-evidence-*/
```

### 2. Vulnerability Assessment
```bash
# Scan sandbox container images for vulnerabilities
trivy image phishnet/sandbox:latest --format json > /tmp/sandbox-vulnerabilities.json

# Check for known CVEs in sandbox runtime
kubectl exec -n phishnet deployment/security-scanner -- /opt/scanner/runtime-cve-check.sh

# Review sandbox configuration for misconfigurations
kubectl get pod -n phishnet -l app=phishnet-sandbox -o yaml | security-audit-tool
```

### 3. Rebuild Sandbox Infrastructure
```bash
# Build new hardened sandbox image
cat << EOF > Dockerfile.sandbox-hardened
FROM ubuntu:22.04

# Security hardening
RUN apt-get update && apt-get install -y \
    apparmor \
    seccomp \
    && rm -rf /var/lib/apt/lists/*

# Add additional security measures
COPY security-profiles/ /opt/security/
COPY sandbox-monitor.sh /usr/local/bin/

# Non-root user
RUN useradd -m -s /bin/bash sandboxuser
USER sandboxuser

# Security labels
LABEL security.hardened=true
LABEL security.version=v2.0

CMD ["/usr/local/bin/sandbox-monitor.sh"]
EOF

# Build and deploy hardened image
docker build -f Dockerfile.sandbox-hardened -t phishnet/sandbox:hardened-$(date +%s) .
```

### 4. Enhance Security Controls
```bash
# Deploy additional security monitoring
cat << EOF | kubectl apply -f -
apiVersion: v1
kind: ConfigMap
metadata:
  name: enhanced-security-config
  namespace: phishnet
data:
  falco-rules: |
    - rule: Sandbox Outbound Connection
      desc: Detect outbound connections from sandbox
      condition: outbound and container.image.tag startswith "phishnet/sandbox"
      output: "Sandbox outbound connection (container=%container.name dest=%fd.rip)"
      priority: CRITICAL
    
    - rule: Sandbox Process Anomaly
      desc: Detect unusual processes in sandbox
      condition: spawned_process and container.image.tag startswith "phishnet/sandbox" and not proc.name in (expected_processes)
      output: "Unusual process in sandbox (container=%container.name process=%proc.name)"
      priority: HIGH
EOF

# Deploy network monitoring
kubectl apply -f k8s/security/network-monitoring.yaml
```

## Recovery (2-4 hours)

### 1. Validate Clean Environment
```bash
# Security scan of entire environment
kubectl create job security-full-scan --image=security-scanner:latest -- /opt/scanner/full-environment-scan.sh

# Wait for scan completion
kubectl wait --for=condition=complete job/security-full-scan --timeout=1800s

# Review scan results
kubectl logs job/security-full-scan
```

### 2. Gradual Service Restoration
```bash
# Enable sandbox with enhanced monitoring
kubectl patch configmap phishnet-api-config -n phishnet -p '{"data":{"SANDBOX_ENABLED":"true","SANDBOX_ENHANCED_MONITORING":"true"}}'

# Deploy single sandbox instance for testing
kubectl scale deployment phishnet-sandbox --replicas=1 -n phishnet

# Test with known-safe file
TEST_FILE="eicar-test-signature.txt"
kubectl exec -n phishnet deployment/phishnet-api -- curl -X POST \
  -F "file=@/opt/test-files/$TEST_FILE" \
  http://localhost:8000/api/v1/files/analyze

# Monitor test analysis
kubectl logs -n phishnet deployment/phishnet-sandbox --follow --timeout=300s
```

### 3. Update Network Policies
```bash
# Replace isolation policy with restricted policy
cat << EOF | kubectl apply -f -
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: sandbox-restricted-access
  namespace: phishnet
spec:
  podSelector:
    matchLabels:
      app: phishnet-sandbox
  policyTypes:
  - Ingress
  - Egress
  ingress:
  - from:
    - podSelector:
        matchLabels:
          app: phishnet-api
    ports:
    - protocol: TCP
      port: 8080
  egress:
  - to: []
    ports:
    - protocol: UDP
      port: 53  # DNS only
  # No other egress allowed
EOF
```

### 4. Resume Normal Operations
```bash
# Gradually scale up sandbox instances
kubectl scale deployment phishnet-sandbox --replicas=2 -n phishnet
sleep 300

# Monitor for 15 minutes
kubectl logs -n phishnet deployment/phishnet-sandbox --since=15m | grep -i error

# If no issues, scale to normal capacity
kubectl scale deployment phishnet-sandbox --replicas=3 -n phishnet

# Re-enable automated file processing
kubectl patch configmap phishnet-api-config -n phishnet -p '{"data":{"AUTOMATED_ANALYSIS":"true"}}'
```

## Post-Incident Actions

### 1. Security Assessment
```bash
# Generate comprehensive security report
cat << EOF > /tmp/security-assessment.md
# PhishNet Sandbox Compromise Security Assessment

## Incident Summary
- **Date**: $(date)
- **Duration**: [X] hours
- **Root Cause**: [Detailed analysis]
- **Impact**: [Business and security impact]

## Vulnerabilities Identified
- [List of vulnerabilities found]
- [Configuration weaknesses]
- [Process gaps]

## Remediation Actions
- [Security improvements implemented]
- [Process changes]
- [Technology updates]

## Recommendations
- [Long-term security enhancements]
- [Monitoring improvements]
- [Training requirements]
EOF
```

### 2. Implement Long-term Improvements
```bash
# Deploy advanced sandbox monitoring
kubectl apply -f k8s/security/sandbox-monitoring-enhanced.yaml

# Update security policies
kubectl apply -f k8s/security/pod-security-standards.yaml

# Implement file reputation checking
kubectl patch configmap phishnet-api-config -n phishnet -p '{"data":{"FILE_REPUTATION_CHECKING":"true"}}'
```

### 3. Update Incident Response
```bash
# Update monitoring alerts based on lessons learned
cat << EOF | kubectl apply -f -
apiVersion: monitoring.coreos.com/v1
kind: PrometheusRule
metadata:
  name: enhanced-sandbox-security
  namespace: phishnet
spec:
  groups:
  - name: sandbox-security-enhanced
    rules:
    - alert: SandboxMemorySpike
      expr: rate(container_memory_usage_bytes{pod=~".*sandbox.*"}[5m]) > 0.1
      for: 30s
      labels:
        severity: warning
      annotations:
        summary: "Rapid memory allocation in sandbox"
    
    - alert: SandboxFileSystemModification
      expr: increase(sandbox_filesystem_modifications_total[1m]) > 5
      for: 0s
      labels:
        severity: high
      annotations:
        summary: "Excessive filesystem modifications in sandbox"
EOF
```

## Prevention Measures

### 1. Enhanced Sandboxing
- Implement multiple isolation layers (containers + VMs)
- Use read-only filesystems where possible
- Implement time-limited sandbox sessions
- Add behavioral analysis monitoring

### 2. Network Security
- Zero-trust network policies
- Deep packet inspection
- DNS monitoring and filtering
- Outbound connection blocking

### 3. Runtime Security
- Real-time process monitoring
- System call filtering with seccomp
- AppArmor/SELinux mandatory access controls
- Container runtime security scanning

### 4. Monitoring and Detection
- Behavioral anomaly detection
- File integrity monitoring
- Network traffic analysis
- Resource usage monitoring

## Communication Plan

### Internal Notification
```
Subject: CRITICAL - Sandbox Security Incident Resolved

Security Team,

A potential sandbox compromise was detected and contained at [TIME].

Status: RESOLVED
Impact: Sandbox environment isolated and rebuilt
Duration: [X] hours
Root Cause: [Summary]

Actions Taken:
✓ Immediate isolation of affected sandboxes
✓ Evidence preservation and forensic analysis
✓ Security vulnerability assessment
✓ Environment rebuild with enhanced security
✓ Gradual service restoration with monitoring

Enhanced security measures have been implemented to prevent recurrence.

Detailed incident report: [Link to full report]

- Security Operations Team
```

### Customer Communication
```
Subject: Security Update - Enhanced Sandbox Protection

We conducted a proactive security review of our malware analysis environment that resulted in temporary service limitations.

What happened: During routine security monitoring, we detected potential anomalous activity in our isolated analysis environment.

Actions taken: We immediately isolated the environment, conducted a thorough security assessment, and rebuilt the system with enhanced protections.

Impact: File analysis was temporarily limited for approximately [X] hours. No customer data was compromised.

Current status: Service has been restored with additional security monitoring and protection measures.

We take security extremely seriously and continuously enhance our protective measures.
```

## Escalation Contacts

- **Security Team Lead**: [Contact info]
- **Incident Commander**: [Contact info]
- **CISO**: [Contact info] (for critical incidents)
- **Legal**: [Contact info] (for potential data breach)
- **External**: [Security consultant/vendor]

## Related Documentation

- [Sandbox Security Architecture](../architecture/sandbox-security.md)
- [Network Security Policies](../security/network-policies.md)
- [Incident Response Framework](./incident-response.md)
- [Security Monitoring Playbook](./security-monitoring.md)
