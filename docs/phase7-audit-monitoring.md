# Phase 7 — Database Auditing & Monitoring

Hospital Patient Records System — UIR ESIN ING5, Database Security (Dr. Harazeem)
Implementation: `db/07_audit.sql`, `app/secure/audit.php`

---

## 1. Two complementary layers

| Layer | Captures | Records |
|-------|----------|---------|
| **Application log** (`audit.php`) | login success/failure, logout, patient search, sensitive-record views, authorization denials | human user, action, IP, user-agent |
| **Database triggers** (`07_audit.sql`) | INSERT/UPDATE/DELETE on `medical_records`, `billing`, `patients`; account changes on `app_users` | DB user + human user (`@app_user`), table, row id, change metadata |

The app layer sees *reads and intent*; triggers see *writes at the database*, even if someone bypasses the app and connects directly. Together they are hard to evade.

## 2. The five investigation questions

Every entry answers:

| Question | Column |
|----------|--------|
| Who performed the activity? | `username` (human) + `db_user` (CURRENT_USER) |
| What action? | `action` |
| When? | `event_time` (microsecond precision) |
| Which resource? | `resource`, `resource_id` |
| Was it successful? | `success` |

The human identity reaches the triggers because the app runs `SET @app_user = <username>` per request (`set_db_actor()`); triggers log `COALESCE(@app_user, CURRENT_USER())`.

## 3. Tamper resistance

- The application account (`app_svc`) has **INSERT-only** on `audit_log` — it can append but cannot `UPDATE`/`DELETE` its own trail.
- `details` stores only metadata (which row changed, whether status/role changed) — **never** diagnosis text or decrypted values, so the audit log is not itself a data-leak vector.

## 4. Detection (feeds Phase 10)

Two views ship with the schema:
- `v_failed_logins` — usernames/IPs with ≥ 3 failed logins.
- `v_sensitive_access` — timeline of sensitive reads, modifications, deletions and account changes.

## 5. Verification (tested)

Simulated activity produced correct records:

| Event generated | Logged as |
|-----------------|-----------|
| `UPDATE medical_records` (as dr.amrani) | `dr.amrani · UPDATE · medical_records · #1 · success` |
| `UPDATE billing status→paid` (as billing) | `billing · UPDATE · billing · #2` |
| `DELETE billing` (as billing) | `billing · DELETE · billing · #3` |
| lock account (as admin) | `admin · ACCOUNT_CHANGE · app_users · #9` |
| 3× failed login (admin from 192.168.56.30) | surfaced by `v_failed_logins` (fails=3) |

The failed-login view immediately flagged the brute-force source IP — demonstrating how the collected data supports detection and investigation of suspicious activity.
