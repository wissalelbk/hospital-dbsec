# Phase 4 & 5 — Vulnerability Analysis, SQL Injection Investigation & Remediation

Hospital Patient Records System — UIR ESIN ING5, Database Security (Dr. Harazeem)

Follows the required grid: **Vulnerability → Impact → Root Cause → Mitigation → Verification.**

---

## 1. The controlled vulnerability (Phase 4)

The deliberately vulnerable component is the **login** and **patient-search** code in `app/vulnerable/`. Both build SQL by concatenating untrusted input:

```php
// login.php (baseline)
$sql = "... WHERE u.username = '$username' AND u.password_hash = '$password'";
// search.php (baseline)
$sql = "... WHERE last_name LIKE '%$q%' OR first_name LIKE '%$q%'";
```

Combined with the baseline's `root` DB connection and cleartext passwords, this single flaw class enables authentication bypass, full data exfiltration, modification and destruction (see `guides/01-attack-guide.md`, attacks A1–A3).

---

## 2. Vulnerability / Impact / Root Cause

| Item | Detail |
|------|--------|
| **Vulnerability** | SQL injection (CWE-89) in login and patient search |
| **Security impact** | Auth bypass as admin; dump of all PII/PHI and cleartext passwords; data tampering; with the root connection, full DBMS takeover |
| **Root cause** | Untrusted input concatenated into SQL strings; no parameterization; no server-side validation; verbose DB errors; over-privileged DB account; plaintext passwords |

---

## 3. Mitigation (Phase 5)

Implemented in `app/secure/`:

1. **Prepared statements / parameterized queries** — all queries use bound parameters (PDO, `ATTR_EMULATE_PREPARES=false` → true server-side prepares). Input is data, never code.
   ```php
   $stmt = db()->prepare('... WHERE username = ?');   // auth.php
   $stmt->execute([$username]);
   ```
2. **Server-side input validation & typing** — e.g. `record.php` casts `patient_id` to `(int)`; search binds the term.
3. **Secure error handling** — PDO exceptions are logged, never echoed; users see a generic message (no SQL leakage).
4. **Least-privileged application account** — `app_svc` (Phase 2) bounds any residual injection to six tables, read/write, no DDL/`mysql.*` (defense in depth).
5. **Secure password handling** — Argon2id + `password_verify()` (Phase 3) means a dumped hash is not a usable password.

> **Note on where the fix lives.** Parameterization is the control that actually *closes* the injection. Least privilege, encryption and hashing limit the damage of any injection that might still occur elsewhere — layered defense, as the brief expects.

A real bug was found and fixed during verification: reusing one named placeholder twice fails under server-side prepares (`SQLSTATE[HY093]`); the search now binds two distinct parameters. (Documented because "explain the evidence" is required.)

---

## 4. Verification — Before / After (tested)

| Test (same payload) | Baseline (`app/vulnerable`) | Hardened (`app/secure`) |
|---------------------|------------------------------|--------------------------|
| Login `username=zzz`, `password=' OR username='admin` | ✅ logged in as **admin / DBA** | ⛔ **DENIED** |
| Login `username=admin`, `password=' OR '1'='1` | ✅ logged in | ⛔ **DENIED** |
| Login `username=admin'/*`, `password=*/ OR '1'='1` | ✅ logged in | ⛔ **DENIED** |
| Search `%' UNION SELECT … FROM app_users-- -` | ✅ dumped all users + cleartext passwords | ⛔ **0 rows** (literal string) |
| Search `' OR '1'='1` | ✅ returned all patients | ⛔ **0 rows** |
| Normal search `Alaoui` | ✅ works | ✅ works (national_id decrypted for display) |

**Conclusion:** every injection that compromised the baseline is no longer exploitable against the hardened application, while legitimate functionality is preserved — satisfying the Phase 5 condition *"Same Test → Vulnerability no longer exploitable."*
