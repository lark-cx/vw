## 17. Backup Strategy

3-2-1 rule: 3 copies, 2 different locations, 1 offsite. A password manager with no backup is a single point of failure.

### Backup script

Executable scripts live in `/usr/local/sbin` — not on the noexec `/srv/data` volume.

```shell
cat > /usr/local/sbin/vaultwarden-backup.sh << 'SCRIPT'
#!/bin/bash
set -euo pipefail

BACKUP_DIR="/srv/data/vaultwarden/backups"
DATE=$(date +%Y%m%d_%H%M%S)
mkdir -p "$BACKUP_DIR"

log() { echo "[$(date '+%H:%M:%S')] $*"; }

log "Starting backup — $DATE"

# SQLite live backup — safe on running database, no container stop needed
docker exec vaultwarden sqlite3 /data/vaultwarden.db \
  ".backup /data/vaultwarden-backup.db"
cp /srv/data/vaultwarden/vw-data/vaultwarden-backup.db \
   "$BACKUP_DIR/db_${DATE}.db"
gzip "$BACKUP_DIR/db_${DATE}.db"
log "Database backed up"

# Attachments and config
tar czf "$BACKUP_DIR/vwdata_${DATE}.tar.gz" \
  -C /srv/data/vaultwarden vw-data \
  --exclude='vw-data/vaultwarden.log' \
  --exclude='vw-data/vaultwarden-backup.db'
log "Application data backed up"

# LUKS headers — without these, encrypted volumes are permanently unrecoverable
VOL_DOCKER="/dev/disk/by-id/scsi-0DO_Volume_vaultwarden-docker"
VOL_DATA="/dev/disk/by-id/scsi-0DO_Volume_vaultwarden-data"
cryptsetup luksHeaderBackup "$VOL_DOCKER" \
  --header-backup-file "$BACKUP_DIR/luks_docker_${DATE}.bak"
cryptsetup luksHeaderBackup "$VOL_DATA" \
  --header-backup-file "$BACKUP_DIR/luks_data_${DATE}.bak"
log "LUKS headers backed up"

# Retention
find "$BACKUP_DIR" -name "*.db.gz"  -mtime +30 -delete
find "$BACKUP_DIR" -name "*.tar.gz" -mtime +30 -delete
find "$BACKUP_DIR" -name "*.bak"    -mtime +7  -delete

log "Complete. Size: $(du -sh $BACKUP_DIR | cut -f1)"

# Notify on backup completion
/usr/local/bin/ntfy-alert.sh \
  "Backup complete" \
  "Vaultwarden backup finished at $(date '+%H:%M') — $(du -sh $BACKUP_DIR | cut -f1)" \
  "min"
SCRIPT

chmod +x /usr/local/sbin/vaultwarden-backup.sh

cat > /etc/cron.d/vaultwarden-backup << 'EOF'
0 2 * * * root /usr/local/sbin/vaultwarden-backup.sh >> /var/log/vaultwarden-backup.log 2>&1
EOF
```

### Test restore (before you need it)

```shell
mkdir -p /tmp/restore-test
latest=$(ls -t /srv/data/vaultwarden/backups/*.db.gz | head -1)
gunzip -c "$latest" > /tmp/restore-test/restore.db
sqlite3 /tmp/restore-test/restore.db "PRAGMA integrity_check;"

# Compare record count to production
sqlite3 /tmp/restore-test/restore.db "SELECT COUNT(*) FROM cipher;"
sqlite3 /srv/data/vaultwarden/vw-data/vaultwarden.db "SELECT COUNT(*) FROM cipher;"

rm -rf /tmp/restore-test
echo "Restore test passed"
```

---

