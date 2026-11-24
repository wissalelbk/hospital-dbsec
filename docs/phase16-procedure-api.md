# Phase 16 (v3) — Stored-procedure API (query allow-listing)

Deepens Phases 2/5/9. File: `db/15_procedure_api.sql`.

## Idea
Remove **all** direct table privileges from the application account and expose only a small, fixed set of **parameterized stored procedures** (`SQL SECURITY DEFINER`). The database attack surface collapses to the procedure signatures: even a fully compromised application — or a residual injection — can no longer run arbitrary SQL. It can only invoke the allow-listed operations with typed, bound parameters.

## API
`sp_login_lookup`, `sp_find_patient` (by blind index), `sp_list_records`, `sp_add_record`, `sp_update_billing_status`, `sp_audit_write`. The app account gets `EXECUTE` on these only — **no** `SELECT/INSERT/UPDATE` on any table.

## Verified (5/5)
- `app_api` **cannot** `SELECT * FROM patients` → `ERROR 1142` (and same for `app_users`).
- `app_api` **can** `CALL sp_find_patient(?)` → returns the correct patient; `CALL sp_list_records(1)` returns the records.
- An injection passed as a procedure parameter (`sp_login_lookup("admin' OR '1'='1")`) is treated as a **literal value** → 0 rows, no injection.

## Why it matters
This is the strongest containment in the project: it enforces *least privilege at the operation level*, not just the table level. Combined with the least-privileged `app_svc` (Phase 2) and prepared statements (Phase 5), a compromised web tier cannot read or modify anything the procedures do not explicitly allow.
