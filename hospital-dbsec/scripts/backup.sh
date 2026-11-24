#!/usr/bin/env bash
# =====================================================================
#  Phase 8 — Database backup  (run on db-vm)
#  Strategy: nightly full logical dump + binary logs for point-in-time
#  recovery (PITR). Dumps include triggers and routines. Backups are
#  stored with restricted permissions (they contain sensitive data).
# =====================================================================
set -euo pipefail

DB="hospital"
BK_DIR="/var/backups/hospital"
STAMP="$(date +%F_%H%M%S)"
OUT="${BK_DIR}/${DB}_${STAMP}.sql.gz"

mkdir -p "$BK_DIR"
chmod 700 "$BK_DIR"

# --single-transaction: consistent snapshot without locking (InnoDB)
# --routines --triggers: include stored programs and the audit triggers
# --source-data=2: record the binlog position for point-in-time recovery
mysqldump --single-transaction --routines --triggers --source-data=2 \
          --databases "$DB" | gzip > "$OUT"

chmod 600 "$OUT"
echo "Backup written: $OUT"

# Retention: keep 14 days
find "$BK_DIR" -name "${DB}_*.sql.gz" -mtime +14 -delete

# NOTE on PITR: ensure binary logging is enabled on db-vm
#   [mysqld] log_bin = /var/log/mysql/binlog
# To recover to a point in time after restoring the dump:
#   mysqlbinlog --start-position=<pos> /var/log/mysql/binlog.000NNN | mysql hospital
