# Phase 8 — Backup & Recovery

Hospital Patient Records System — UIR ESIN ING5, Database Security (Dr. Harazeem)
Implementation: `scripts/backup.sh`, `scripts/restore.sh`

---

## 1. Strategy

| Element | Choice | Why |
|---------|--------|-----|
| Backup type | Nightly full logical dump (`mysqldump --single-transaction`) + **binary logs** | Consistent InnoDB snapshot without locking; binlogs enable point-in-time recovery between dumps |
| Contents | `--routines --triggers` | The audit triggers and any stored programs must survive a restore |
| Storage | `/var/backups/hospital`, `chmod 700`, dumps `chmod 600` | Backups contain sensitive data — they get the same protection as the DB |
| Retention | 14 days | Balance of recoverability and footprint |
| PITR | `--source-data=2` records binlog position; replay with `mysqlbinlog` | Recover to the moment just before an incident |

> A backup that contains plaintext of the sensitive columns would reintroduce the Phase 6 risk. Because those columns are stored **encrypted** and the AES key lives on app-vm (not in the dump), a stolen backup still yields only ciphertext.

## 2. Procedure

Backup (on db-vm, nightly cron):
```bash
./scripts/backup.sh          # → /var/backups/hospital/hospital_<stamp>.sql.gz
```
Restore:
```bash
./scripts/restore.sh /var/backups/hospital/hospital_<stamp>.sql.gz
```

## 3. Recovery scenario (required: demonstrate real recovery)

Simulated incident: a critical table is accidentally dropped and an invoice is deleted.

| Step | Action | Observed |
|------|--------|----------|
| Baseline | — | medical_records = 5, prescriptions = 4, billing = 3 |
| Loss | `DROP TABLE medical_records` + `DELETE billing invoice #1` | **medical_records table gone**, billing = 2 |
| Restore | `restore.sh <backup>` | medical_records = 5, prescriptions = 4, billing = 3 |
| Verify | counts + `CHECKSUM TABLE` + FK check | checksums identical to pre-loss; **0 orphan prescriptions**; 8 triggers restored |

**Conclusion:** the system was restored to a verified-correct operational state — table structure, all rows, referential integrity and the audit triggers — proving genuine recovery, not merely the existence of a backup file (which the brief explicitly says is insufficient).

## 4. Hardening the backups (ties to Phase 9)

- Restrict directory/file permissions (done in `backup.sh`).
- Store a copy off the DB host (offline/again-encrypted) so a host compromise doesn't take the backups with it.
- Periodically **test** restores (a backup never tested is not a backup).
