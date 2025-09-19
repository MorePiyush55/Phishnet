#!/bin/bash

# Database backup script for PhishNet
# Supports full backups, incremental backups, and cleanup

set -e

# Configuration
POSTGRES_HOST="${POSTGRES_HOST:-postgres}"
POSTGRES_PORT="${POSTGRES_PORT:-5432}"
POSTGRES_DB="${POSTGRES_DB:-phishnet}"
POSTGRES_USER="${POSTGRES_USER:-phishnet_user}"
BACKUP_DIR="${BACKUP_DIR:-/backups}"
RETENTION_DAYS="${RETENTION_DAYS:-30}"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

# Create backup directory
mkdir -p "$BACKUP_DIR/database"
mkdir -p "$BACKUP_DIR/logs"

# Function to log messages
log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" | tee -a "$BACKUP_DIR/logs/backup.log"
}

# Function to perform full database backup
backup_database() {
    local backup_file="$BACKUP_DIR/database/phishnet_full_${TIMESTAMP}.sql.gz"
    
    log "Starting database backup..."
    
    if pg_dump -h "$POSTGRES_HOST" -p "$POSTGRES_PORT" -U "$POSTGRES_USER" -d "$POSTGRES_DB" \
        --no-password --verbose --format=custom --compress=9 \
        --file="$backup_file.tmp"; then
        
        mv "$backup_file.tmp" "$backup_file"
        log "Database backup completed: $backup_file"
        
        # Verify backup
        if pg_restore --list "$backup_file" >/dev/null 2>&1; then
            log "Backup verification successful"
        else
            log "ERROR: Backup verification failed"
            exit 1
        fi
    else
        log "ERROR: Database backup failed"
        exit 1
    fi
}

# Function to backup specific tables for incremental backups
backup_incremental() {
    local backup_file="$BACKUP_DIR/database/phishnet_incremental_${TIMESTAMP}.sql.gz"
    local since_time="${1:-24 hours ago}"
    
    log "Starting incremental backup since: $since_time"
    
    # Export data modified since last backup
    psql -h "$POSTGRES_HOST" -p "$POSTGRES_PORT" -U "$POSTGRES_USER" -d "$POSTGRES_DB" \
        --no-password -c "\\copy (
            SELECT * FROM emails WHERE updated_at >= NOW() - INTERVAL '$since_time'
            UNION ALL
            SELECT * FROM analysis_results WHERE created_at >= NOW() - INTERVAL '$since_time'
            UNION ALL
            SELECT * FROM audit_logs WHERE created_at >= NOW() - INTERVAL '$since_time'
        ) TO STDOUT WITH CSV HEADER" | gzip > "$backup_file"
    
    log "Incremental backup completed: $backup_file"
}

# Function to cleanup old backups
cleanup_old_backups() {
    log "Cleaning up backups older than $RETENTION_DAYS days..."
    
    find "$BACKUP_DIR/database" -name "*.sql.gz" -type f -mtime +$RETENTION_DAYS -delete
    find "$BACKUP_DIR/logs" -name "*.log" -type f -mtime +$RETENTION_DAYS -delete
    
    log "Cleanup completed"
}

# Function to create backup manifest
create_manifest() {
    local manifest_file="$BACKUP_DIR/manifest_${TIMESTAMP}.json"
    
    cat > "$manifest_file" <<EOF
{
    "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
    "backup_type": "$1",
    "database": "$POSTGRES_DB",
    "files": [
        $(find "$BACKUP_DIR/database" -name "*${TIMESTAMP}*" -printf '"%f",\n' | sed '$s/,$//')
    ],
    "retention_days": $RETENTION_DAYS,
    "total_size": "$(du -sh "$BACKUP_DIR/database" | cut -f1)"
}
EOF
    
    log "Backup manifest created: $manifest_file"
}

# Main execution
case "${1:-full}" in
    "full")
        backup_database
        create_manifest "full"
        ;;
    "incremental")
        backup_incremental "${2:-24 hours}"
        create_manifest "incremental"
        ;;
    "cleanup")
        cleanup_old_backups
        ;;
    *)
        log "Usage: $0 {full|incremental|cleanup} [since_time]"
        exit 1
        ;;
esac

# Always cleanup old backups after successful backup
if [[ "${1:-full}" != "cleanup" ]]; then
    cleanup_old_backups
fi

log "Backup operation completed successfully"
