#!/usr/bin/env bash
# =====================================================================
#  Phase 8 — Database restore  (run on db-vm)
#  Usage: ./restore.sh /var/backups/hospital/hospital_<stamp>.sql.gz
# =====================================================================
set -euo pipefail

BK="${1:?usage: restore.sh <backup.sql.gz>}"
[ -r "$BK" ] || { echo "Backup not readable: $BK" >&2; exit 1; }

echo "Restoring from $BK ..."
gunzip -c "$BK" | mysql
echo "Restore complete."

# Integrity verification (counts + checksums)
mysql -e "
  SELECT 'patients' t, COUNT(*) n FROM hospital.patients
  UNION ALL SELECT 'medical_records', COUNT(*) FROM hospital.medical_records
  UNION ALL SELECT 'billing', COUNT(*) FROM hospital.billing;"
mysql -e "CHECKSUM TABLE hospital.patients, hospital.medical_records, hospital.billing;"
