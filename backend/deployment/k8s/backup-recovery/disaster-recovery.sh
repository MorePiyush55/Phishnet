#!/bin/bash

# PhishNet Disaster Recovery Script
# This script orchestrates the complete disaster recovery process

set -euo pipefail

# Configuration
NAMESPACE="phishnet"
BACKUP_STORAGE_PATH="/backups"
RECOVERY_LOG="/var/log/phishnet-recovery.log"
DRY_RUN=${DRY_RUN:-false}

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging function
log() {
    local level=$1
    shift
    local message="$@"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    case $level in
        INFO)  echo -e "${GREEN}[INFO]${NC} ${timestamp} - $message" | tee -a $RECOVERY_LOG ;;
        WARN)  echo -e "${YELLOW}[WARN]${NC} ${timestamp} - $message" | tee -a $RECOVERY_LOG ;;
        ERROR) echo -e "${RED}[ERROR]${NC} ${timestamp} - $message" | tee -a $RECOVERY_LOG ;;
        DEBUG) echo -e "${BLUE}[DEBUG]${NC} ${timestamp} - $message" | tee -a $RECOVERY_LOG ;;
    esac
}

# Error handling
error_exit() {
    log ERROR "$1"
    log ERROR "Recovery process failed. Manual intervention required."
    exit 1
}

# Trap errors
trap 'error_exit "Unexpected error occurred at line $LINENO"' ERR

# Validate prerequisites
validate_prerequisites() {
    log INFO "Validating prerequisites..."
    
    # Check kubectl access
    if ! kubectl cluster-info &>/dev/null; then
        error_exit "kubectl is not configured or cluster is unreachable"
    fi
    
    # Check namespace exists
    if ! kubectl get namespace $NAMESPACE &>/dev/null; then
        error_exit "Namespace $NAMESPACE does not exist"
    fi
    
    # Check backup storage accessibility
    if ! kubectl get pvc backup-storage -n $NAMESPACE &>/dev/null; then
        error_exit "Backup storage PVC not found"
    fi
    
    log INFO "Prerequisites validated successfully"
}

# List available backups
list_backups() {
    log INFO "Available database backups:"
    kubectl exec -n $NAMESPACE deployment/phishnet-api -- ls -la $BACKUP_STORAGE_PATH/phishnet_backup_*.sql.gz 2>/dev/null || {
        log WARN "No database backups found"
    }
    
    log INFO "Available Redis backups:"
    kubectl exec -n $NAMESPACE deployment/phishnet-api -- ls -la $BACKUP_STORAGE_PATH/redis_backup_*.rdb.gz 2>/dev/null || {
        log WARN "No Redis backups found"
    }
    
    log INFO "Available volume snapshots:"
    kubectl get volumesnapshots -n $NAMESPACE --sort-by=.metadata.creationTimestamp
}

# Verify backup integrity
verify_backup() {
    local backup_file=$1
    local backup_type=$2
    
    log INFO "Verifying backup integrity: $backup_file"
    
    case $backup_type in
        postgres)
            # Verify PostgreSQL backup
            kubectl exec -n $NAMESPACE statefulset/postgres -- bash -c "
                pg_restore --list $backup_file &>/dev/null && echo 'Backup verification: PASSED' || echo 'Backup verification: FAILED'
            "
            ;;
        redis)
            # Verify Redis backup (check if file is valid gzip)
            kubectl exec -n $NAMESPACE statefulset/redis -- bash -c "
                gzip -t $backup_file && echo 'Backup verification: PASSED' || echo 'Backup verification: FAILED'
            "
            ;;
    esac
    
    # Verify checksum if metadata exists
    local meta_file="${backup_file}.meta"
    if kubectl exec -n $NAMESPACE deployment/phishnet-api -- test -f "$meta_file" 2>/dev/null; then
        log INFO "Verifying backup checksum..."
        kubectl exec -n $NAMESPACE deployment/phishnet-api -- bash -c "
            STORED_CHECKSUM=\$(jq -r '.checksum_sha256' $meta_file)
            ACTUAL_CHECKSUM=\$(sha256sum $backup_file | cut -d' ' -f1)
            if [ \"\$STORED_CHECKSUM\" = \"\$ACTUAL_CHECKSUM\" ]; then
                echo 'Checksum verification: PASSED'
            else
                echo 'Checksum verification: FAILED'
                exit 1
            fi
        "
    fi
}

# Scale down applications
scale_down_applications() {
    log INFO "Scaling down application services..."
    
    if [ "$DRY_RUN" = "true" ]; then
        log INFO "[DRY RUN] Would scale down deployments"
        return
    fi
    
    # Scale down API servers
    kubectl scale deployment phishnet-api --replicas=0 -n $NAMESPACE
    kubectl scale deployment phishnet-frontend --replicas=0 -n $NAMESPACE
    
    # Scale down workers
    kubectl scale deployment phishnet-worker-email --replicas=0 -n $NAMESPACE
    kubectl scale deployment phishnet-worker-analysis --replicas=0 -n $NAMESPACE
    kubectl scale deployment phishnet-worker-redirect --replicas=0 -n $NAMESPACE
    
    # Wait for pods to terminate
    log INFO "Waiting for pods to terminate..."
    kubectl wait --for=delete pods -l app.kubernetes.io/name=phishnet -n $NAMESPACE --timeout=300s
    
    log INFO "Application services scaled down"
}

# Restore PostgreSQL database
restore_postgres() {
    local backup_file=$1
    
    log INFO "Starting PostgreSQL database restore from: $backup_file"
    
    # Verify backup before restore
    verify_backup "$backup_file" "postgres"
    
    if [ "$DRY_RUN" = "true" ]; then
        log INFO "[DRY RUN] Would restore PostgreSQL from $backup_file"
        return
    fi
    
    # Create restore job
    cat <<EOF | kubectl apply -f -
apiVersion: batch/v1
kind: Job
metadata:
  name: postgres-restore-$(date +%s)
  namespace: $NAMESPACE
spec:
  ttlSecondsAfterFinished: 3600
  template:
    spec:
      restartPolicy: Never
      containers:
      - name: postgres-restore
        image: postgres:15-alpine
        command:
        - /bin/bash
        - -c
        - |
          set -euo pipefail
          export PGPASSWORD="\${POSTGRES_PASSWORD}"
          
          echo "Starting database restore..."
          
          # Drop existing connections
          psql -h postgres -p 5432 -U phishnet_user -d postgres -c "
            SELECT pg_terminate_backend(pid) 
            FROM pg_stat_activity 
            WHERE datname = 'phishnet' AND pid <> pg_backend_pid();
          "
          
          # Restore database
          pg_restore -h postgres -p 5432 -U phishnet_user -d phishnet \\
            --clean --verbose --single-transaction \\
            --if-exists --no-owner --no-privileges \\
            "$backup_file"
          
          echo "Database restore completed successfully"
        env:
        - name: POSTGRES_PASSWORD
          valueFrom:
            secretKeyRef:
              name: phishnet-database-secrets
              key: postgres-password
        volumeMounts:
        - name: backup-storage
          mountPath: /backups
        resources:
          requests:
            memory: "512Mi"
            cpu: "200m"
          limits:
            memory: "1Gi"
            cpu: "500m"
      volumes:
      - name: backup-storage
        persistentVolumeClaim:
          claimName: backup-storage
EOF
    
    # Wait for restore job to complete
    local job_name=$(kubectl get jobs -n $NAMESPACE --sort-by=.metadata.creationTimestamp -o name | tail -1)
    kubectl wait --for=condition=complete $job_name -n $NAMESPACE --timeout=1800s
    
    log INFO "PostgreSQL database restore completed"
}

# Restore Redis
restore_redis() {
    local backup_file=$1
    
    log INFO "Starting Redis restore from: $backup_file"
    
    # Verify backup before restore
    verify_backup "$backup_file" "redis"
    
    if [ "$DRY_RUN" = "true" ]; then
        log INFO "[DRY RUN] Would restore Redis from $backup_file"
        return
    fi
    
    # Scale down Redis
    kubectl scale statefulset redis --replicas=0 -n $NAMESPACE
    kubectl wait --for=delete pods -l app=redis -n $NAMESPACE --timeout=300s
    
    # Restore Redis data
    kubectl run redis-restore --rm -i --restart=Never --image=redis:7-alpine -n $NAMESPACE -- bash -c "
        # Extract backup to Redis data directory
        gunzip -c $backup_file > /data/dump.rdb
        chown 999:999 /data/dump.rdb
        chmod 644 /data/dump.rdb
        echo 'Redis backup extracted successfully'
    " --overrides='
    {
      "spec": {
        "containers": [{
          "name": "redis-restore",
          "image": "redis:7-alpine",
          "volumeMounts": [{
            "name": "backup-storage",
            "mountPath": "/backups"
          }, {
            "name": "redis-data",
            "mountPath": "/data"
          }]
        }],
        "volumes": [{
          "name": "backup-storage",
          "persistentVolumeClaim": {
            "claimName": "backup-storage"
          }
        }, {
          "name": "redis-data",
          "persistentVolumeClaim": {
            "claimName": "redis-data-redis-0"
          }
        }]
      }
    }'
    
    # Scale up Redis
    kubectl scale statefulset redis --replicas=1 -n $NAMESPACE
    kubectl wait --for=condition=ready pod/redis-0 -n $NAMESPACE --timeout=300s
    
    log INFO "Redis restore completed"
}

# Restore from volume snapshot
restore_from_snapshot() {
    local snapshot_name=$1
    local target_pvc=$2
    
    log INFO "Restoring from volume snapshot: $snapshot_name to PVC: $target_pvc"
    
    if [ "$DRY_RUN" = "true" ]; then
        log INFO "[DRY RUN] Would restore from snapshot $snapshot_name to $target_pvc"
        return
    fi
    
    # Create new PVC from snapshot
    cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: ${target_pvc}-restored
  namespace: $NAMESPACE
spec:
  accessModes:
    - ReadWriteOnce
  storageClassName: fast-ssd
  resources:
    requests:
      storage: 100Gi
  dataSource:
    name: $snapshot_name
    kind: VolumeSnapshot
    apiGroup: snapshot.storage.k8s.io
EOF
    
    kubectl wait --for=condition=Bound pvc/${target_pvc}-restored -n $NAMESPACE --timeout=300s
    
    log INFO "Volume snapshot restore completed"
}

# Scale up applications
scale_up_applications() {
    log INFO "Scaling up application services..."
    
    if [ "$DRY_RUN" = "true" ]; then
        log INFO "[DRY RUN] Would scale up deployments"
        return
    fi
    
    # Scale up databases first
    kubectl scale statefulset postgres --replicas=1 -n $NAMESPACE
    kubectl scale statefulset redis --replicas=1 -n $NAMESPACE
    
    # Wait for databases to be ready
    kubectl wait --for=condition=ready pod/postgres-0 -n $NAMESPACE --timeout=300s
    kubectl wait --for=condition=ready pod/redis-0 -n $NAMESPACE --timeout=300s
    
    # Scale up application services
    kubectl scale deployment phishnet-api --replicas=3 -n $NAMESPACE
    kubectl scale deployment phishnet-frontend --replicas=2 -n $NAMESPACE
    kubectl scale deployment phishnet-worker-email --replicas=2 -n $NAMESPACE
    kubectl scale deployment phishnet-worker-analysis --replicas=2 -n $NAMESPACE
    kubectl scale deployment phishnet-worker-redirect --replicas=1 -n $NAMESPACE
    
    # Wait for applications to be ready
    kubectl wait --for=condition=available deployment --all -n $NAMESPACE --timeout=600s
    
    log INFO "Application services scaled up and ready"
}

# Validate system health after recovery
validate_recovery() {
    log INFO "Validating system health after recovery..."
    
    # Check pod status
    log INFO "Pod status:"
    kubectl get pods -n $NAMESPACE
    
    # Check database connectivity
    log INFO "Checking database connectivity..."
    kubectl exec -n $NAMESPACE statefulset/postgres -- pg_isready -h localhost -p 5432
    
    # Check Redis connectivity
    log INFO "Checking Redis connectivity..."
    kubectl exec -n $NAMESPACE statefulset/redis -- redis-cli ping
    
    # Check API health
    log INFO "Checking API health..."
    kubectl exec -n $NAMESPACE deployment/phishnet-api -- curl -f http://localhost:8000/health || {
        log WARN "API health check failed - service may still be starting"
    }
    
    # Check recent database activity
    log INFO "Checking database activity..."
    kubectl exec -n $NAMESPACE statefulset/postgres -- psql -U phishnet_user -d phishnet -c "
        SELECT COUNT(*) as table_count FROM information_schema.tables WHERE table_schema = 'public';
        SELECT NOW() as current_time;
    "
    
    log INFO "System health validation completed"
}

# Main recovery function
perform_recovery() {
    local recovery_type=$1
    local backup_identifier=$2
    
    log INFO "Starting disaster recovery process..."
    log INFO "Recovery type: $recovery_type"
    log INFO "Backup identifier: $backup_identifier"
    
    # Validate prerequisites
    validate_prerequisites
    
    # Scale down applications
    scale_down_applications
    
    case $recovery_type in
        "full")
            log INFO "Performing full system recovery..."
            restore_postgres "$BACKUP_STORAGE_PATH/phishnet_backup_${backup_identifier}.sql.gz"
            restore_redis "$BACKUP_STORAGE_PATH/redis_backup_${backup_identifier}.rdb.gz"
            ;;
        "database-only")
            log INFO "Performing database-only recovery..."
            restore_postgres "$BACKUP_STORAGE_PATH/phishnet_backup_${backup_identifier}.sql.gz"
            ;;
        "redis-only")
            log INFO "Performing Redis-only recovery..."
            restore_redis "$BACKUP_STORAGE_PATH/redis_backup_${backup_identifier}.rdb.gz"
            ;;
        "snapshot")
            log INFO "Performing snapshot-based recovery..."
            restore_from_snapshot "$backup_identifier" "postgres-data-postgres-0"
            ;;
        *)
            error_exit "Invalid recovery type: $recovery_type"
            ;;
    esac
    
    # Scale up applications
    scale_up_applications
    
    # Validate recovery
    validate_recovery
    
    log INFO "Disaster recovery completed successfully!"
    log INFO "Recovery log available at: $RECOVERY_LOG"
}

# Show usage information
show_usage() {
    echo "PhishNet Disaster Recovery Script"
    echo ""
    echo "Usage: $0 <command> [options]"
    echo ""
    echo "Commands:"
    echo "  list                          List available backups and snapshots"
    echo "  verify <backup_file> <type>   Verify backup integrity"
    echo "  recover <type> <identifier>   Perform disaster recovery"
    echo ""
    echo "Recovery Types:"
    echo "  full                         Restore both database and Redis"
    echo "  database-only               Restore only PostgreSQL database"
    echo "  redis-only                  Restore only Redis"
    echo "  snapshot                    Restore from volume snapshot"
    echo ""
    echo "Examples:"
    echo "  $0 list"
    echo "  $0 verify /backups/phishnet_backup_20240101_020000.sql.gz postgres"
    echo "  $0 recover full 20240101_020000"
    echo "  $0 recover snapshot postgres-snapshot-20240101-010000"
    echo ""
    echo "Environment Variables:"
    echo "  DRY_RUN=true                Perform dry run without making changes"
    echo "  NAMESPACE=phishnet          Kubernetes namespace (default: phishnet)"
}

# Main script logic
main() {
    case "${1:-}" in
        "list")
            list_backups
            ;;
        "verify")
            if [ $# -lt 3 ]; then
                echo "Error: verify requires backup file and type"
                show_usage
                exit 1
            fi
            verify_backup "$2" "$3"
            ;;
        "recover")
            if [ $# -lt 3 ]; then
                echo "Error: recover requires recovery type and backup identifier"
                show_usage
                exit 1
            fi
            perform_recovery "$2" "$3"
            ;;
        "help"|"-h"|"--help")
            show_usage
            ;;
        *)
            echo "Error: Invalid command"
            show_usage
            exit 1
            ;;
    esac
}

# Execute main function with all arguments
main "$@"
