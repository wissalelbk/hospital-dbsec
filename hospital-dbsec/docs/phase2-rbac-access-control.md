# Phase 2 — RBAC, Access-Control Matrix & Least Privilege

Hospital Patient Records System — UIR ESIN ING5, Database Security (Dr. Harazeem)
Implementation: `db/04_roles_rbac_SECURE.sql`

---

## 1. User categories

| Role | Who | Needs |
|------|-----|-------|
| DBA | IT / database admin | Full control of the `hospital` schema |
| Doctor | Treating physician | Clinical data (read/write), patient demographics (read) |
| Nurse | Nursing staff | Clinical data (read), appointments (update) |
| Receptionist | Front desk | Demographics + appointments only |
| Accountant | Billing | Billing data + patient name only |
| Patient | Patient portal | Own records (read only) |
| AppService (`app_svc`) | The web application | Minimal DML the app performs on behalf of users |

---

## 2. Access-Control Matrix

`R`=SELECT · `W`=INSERT/UPDATE · `—`=no access · `own`=row-restricted to the user (enforced in the app layer)

| Table | DBA | Doctor | Nurse | Receptionist | Accountant | Patient | app_svc |
|-------|-----|--------|-------|--------------|-----------|---------|---------|
| `patients` | RW+ | R | R | RW | R (name only, via view) | R (own) | RW |
| `medical_records` | RW+ | RW | R | — | — | R (own) | RW |
| `prescriptions` | RW+ | RW | R | — | — | R (own) | RW |
| `lab_results` | RW+ | RW | R | — | — | R (own) | RW |
| `appointments` | RW+ | RW | RW | RW | — | R (own) | RW |
| `billing` | RW+ | — | — | — | RW | R (own) | RW |
| `app_users` | RW+ | — | — | — | — | — | R + update lockout |
| `roles`, `staff` | RW+ | R | R(staff) | R(staff) | — | — | R |
| `mysql.*` (system) | — | — | — | — | — | — | — |

`RW+` = also DDL within `hospital.*` (DBA only). No role has `*.*` privileges or `GRANT OPTION`.

> **Note on patient rows.** Pure SQL `GRANT` cannot express "only your own records", so row-level ownership is enforced in the application (the secure app injects `WHERE patient_id = :session_patient_id`). MySQL 8 VIEWs or a future migration to row-level policies could push this into the DB.

---

## 3. Implementation (CREATE / GRANT / REVOKE / SHOW GRANTS)

### 3.1 Roles and grants (excerpt)
```sql
CREATE ROLE 'role_doctor';
GRANT SELECT, INSERT, UPDATE ON hospital.medical_records TO 'role_doctor';
GRANT SELECT ON hospital.patients TO 'role_doctor';
-- (no grant on billing / app_users → implicit deny)

CREATE USER 'doctor_user'@'192.168.56.%' IDENTIFIED BY 'Doc#Str0ng!2026';
GRANT 'role_doctor' TO 'doctor_user'@'192.168.56.%';
SET DEFAULT ROLE ALL TO 'doctor_user'@'192.168.56.%';
```

### 3.2 Removing the insecure baseline (REVOKE / DROP)
```sql
DROP USER 'root'@'192.168.56.20';   -- app no longer connects as root
DROP USER 'app'@'%';                -- remove the ALL-PRIVILEGES/anywhere account
```

### 3.3 Least-privilege application account
```sql
CREATE USER 'app_svc'@'192.168.56.20' IDENTIFIED BY '...' REQUIRE SSL;
GRANT SELECT, INSERT, UPDATE ON hospital.patients TO 'app_svc'@'192.168.56.20';
-- ... only the tables the app uses; NO DROP/DELETE/FILE/GRANT, NO mysql.*
```

---

## 4. Privilege testing — evidence (tested)

Connecting as the least-privileged doctor account and exercising each boundary:

| Operation attempted | Expected | Actual result |
|---------------------|----------|---------------|
| `SELECT COUNT(*) FROM patients` | allow | ✅ returns 8 |
| `UPDATE medical_records … WHERE record_id=1` | allow | ✅ 1 row updated |
| `SELECT * FROM billing` | deny | ⛔ `ERROR 1142: SELECT command denied … hospital.billing` |
| `SELECT username,password_hash FROM app_users` | deny | ⛔ `ERROR 1142: SELECT command denied … hospital.app_users` |
| `DROP TABLE medical_records` | deny | ⛔ `ERROR 1142: DROP command denied … hospital.medical_records` |
| `SELECT user,host FROM mysql.user` | deny | ⛔ `ERROR 1142: SELECT command denied … mysql.user` |

`SHOW GRANTS` for the account lists exactly the six scoped table grants and nothing else — proof of least privilege.

---

## 5. Why this matters (defense-in-depth, honest scope)

- **Containment of compromise.** In the baseline, the app ran as `root`, so the SQL-injection foothold (attack A2/A3) inherited full control: read every schema, `DROP`, create backdoor users. With `app_svc`, the same foothold is bounded to six `hospital` tables, read/write only — **no `DROP`, no `DELETE`, no `mysql.*`, no new users, no other databases.**
- **Least privilege ≠ SQLi fix.** `app_svc` still legitimately reads the tables the app shows, so least privilege alone does not stop data disclosure through injection. It is one layer. The injection itself is closed by **prepared statements** (Phase 5); the dumped sensitive columns are made useless by **encryption at rest** (Phase 6) and **Argon2id** password hashing (Phase 3). Together these satisfy the before/after proof required by the brief.
- **Separation of duties.** A receptionist cannot read diagnoses; an accountant cannot read clinical notes or national IDs; a doctor cannot read billing. This directly enforces the confidentiality requirements from the Phase 1 CIA analysis.

---

*Deliverables: Access-Control Matrix (§2), user/role/privilege implementation (`db/04`, §3), least-privilege demonstration with privilege-testing evidence (§4). Feeds report sections 9–10.*
