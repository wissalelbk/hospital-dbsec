# Phase 20 (v3) — Anomaly detection & automated response

Deepens Phases 7/10. File: `db/19_anomaly.sql`.

## Idea
Move from *recording* events (Phase 7) and *investigating after the fact* (Phase 10) to **detecting and responding in near-real-time**. `sp_detect_anomalies(threshold, window)` scans the audit log for **bulk access to sensitive data** — a clinician or compromised account reading far more records than normal, a classic exfiltration signal — then:
1. raises a tamper-evident **`ANOMALY_ALERT`** in the audit log, and
2. **auto-locks** the offending account (`locked_until = NOW()+30min`).

It is schedulable as a MariaDB `EVENT` (every minute).

## Verified (3/3)
- A simulated **exfiltration** (30 record views in the window) is **detected** — `v_anomalies` shows `dr.amrani / 30`.
- **Normal** activity (3 views by a nurse) is **not** alerted (no false positive at threshold 20).
- **Automated response**: `dr.amrani` is **locked** immediately.

## Implementation note
Offenders are first materialized into a temporary table, then the account-lock `UPDATE` reads that temp table — not `audit_log` — so the account trigger (which writes to `audit_log`) does not collide with the reading statement (MariaDB `ERROR 1442`). Thresholds should be tuned per role from a real baseline to balance detection against false positives.
