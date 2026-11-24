# Phase 17 (v3) — Dynamic data masking by role

Deepens Phases 2/6. File: `db/16_masking.sql`.

## Idea
RBAC decides **who can read a row**; masking decides **which fields they see in clear**. A single view redacts PII differently by the caller's role (server-set `@app_role`), enforcing data minimization at the database.

## Rules (example)
- `phone`: full for DBA/Doctor/Nurse; `******NN` otherwise.
- `date_of_birth`: full for DBA/Doctor; `YYYY-**-**` otherwise.
- `address`: full for DBA/Doctor/Nurse; first 4 chars + `…` otherwise.

## Verified (3/3)
- As **Doctor**: `0611-000-001`, `1985-04-12`, full address.
- As **Receptionist**: `******01`, `1985-**-**`, `12 R…` — same row, minimized fields.

## Note
Masking complements (does not replace) encryption: `national_id` stays AES-encrypted at rest (Phase 6/13); masking here targets the operational PII a front-desk role should not fully see. Column-level privileges (`GRANT SELECT (col) …`) are a stricter alternative when a role must never touch a column at all.
