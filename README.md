
## 1. What this project is

A **Hospital Patient Records System** built as a database-backed PHP/MySQL application, then taken through the full defensive-security lifecycle required by the brief:

> **Design → Build → Assess → Attack → Test → Secure → Monitor → Recover → Harden → Investigate → Report**

The guiding method is **purple-teaming against our own isolated lab system**:

1. Stand up a deliberately **vulnerable baseline** ("attaque vierge" — no defenses).
2. **Attack** it from a Kali VM and capture proof of compromise.
3. **Remediate**, then **re-attack** to prove the same test now fails.
4. Repeat across every control domain until the system is hardened against current threats, grounded in the **latest published CVEs** (Oracle MySQL Critical Patch Update, Oct 2026) and **OWASP** guidance.


## 2. Lab topology (multi-VM)

| VM | Role | OS | Key software | IP (host-only `vboxnet0`) |
|----|------|----|--------------|---------------------------|
| `db-vm` | Database server | Ubuntu Server 24.04 | MySQL 8.4 LTS | `192.168.56.10` |
| `app-vm` | Application server | Ubuntu Server 24.04 | Apache 2.4 + PHP 8.3 | `192.168.56.20` |
| `kali-vm` | Attacker | Kali Linux 2026.x | sqlmap, hydra, mysql-client, nmap, Burp | `192.168.56.30` |

Full build in [`guides/00-lab-setup-guide.md`](guides/00-lab-setup-guide.md).

---

## 3. Repository layout

```
hospital-dbsec/
├── README.md                     ← this file
├── db/
│   ├── 01_schema.sql             ← baseline schema (sensitive data in CLEAR — the "before")
│   ├── 02_seed.sql               ← realistic sample data
│   ├── 03_app_account_INSECURE.sql ← baseline: app connects as root (the vulnerability)
│   ├── 04_roles_rbac_SECURE.sql  ← [Phase 2] roles, least-privilege app accounts
│   ├── 06_sensitive_data.sql     ← [Phase 6] encrypted columns migration
│   ├── 07_audit.sql              ← [Phase 7] audit tables + triggers
│   └── 09_hardening.sql          ← [Phase 9] hardening statements
├── app/
│   ├── vulnerable/               ← baseline insecure PHP app
│   └── secure/                   ← hardened PHP app
├── docs/
│   ├── phase1-design-security-analysis.md
│   ├── phase2-rbac-access-control.md
│   ├── ...                       ← one doc per phase
│   └── cve-reference.md          ← CVEs this project tracks
├── guides/
│   ├── 00-lab-setup-guide.md     ← implementation per VM
│   ├── 01-attack-guide.md        ← Kali attack playbook (before remediation)
│   └── 02-defense-hardening-guide.md ← defenses + re-test proof
└── report/
    └── security-assessment-report.(md|docx)  ← the 20–25 page deliverable
```

---

## 4. Attack → Defense matrix (the project's backbone)

| # | Phase | Vulnerability (attack vierge) | Attack from Kali | Defense implemented | Grounding |
|---|-------|-------------------------------|------------------|---------------------|-----------|
| A | 4 / 5 | SQL injection on login & patient search (string-concatenated queries) | `sqlmap`, manual `' OR '1'='1`, UNION, blind | Prepared statements, server-side validation, safe error handling | OWASP SQLi / Injection |
| B | 3 | Passwords stored in plaintext | Dump `app_users`, read passwords directly | Argon2id (`m=64MiB,t=3,p=1`), rehash-on-login | OWASP Password Storage (2026) |
| C | 2 | App connects as `root@%` (all privileges) | Use SQLi foothold to read every table, write, `DROP` | Dedicated least-privilege app accounts, RBAC roles | Principle of Least Privilege |
| D | 6 | National ID / insurance / medical in cleartext | Read PII & medical data straight from tables | AES-256 app-side encryption at rest + TLS in transit + key mgmt | Data protection |
| E | 7 | No logging | Attack leaves no trace | Audit tables + triggers + app event logging | Auditability |
| F | 9 | Default accounts, X Plugin exposed, no TLS, unpatched engine | Recon with `nmap`/`mysql`, map to known CVEs | Patch to 8.4.x, disable X Plugin, bind-address, remove anon users, TLS w/ patched OpenSSL | **Oracle CPU Oct 2026** — see `docs/cve-reference.md` |
| G | 8 | No backups | Simulated table drop = permanent loss | `mysqldump` + binary-log point-in-time recovery, tested restore | Recoverability |
| H | 10 | — | Simulated incident (unauthorized access + rogue privileged account) | Reconstruct timeline from audit evidence | Incident response |

---

## 5. How to reproduce

1. Build the three VMs — [`guides/00-lab-setup-guide.md`](guides/00-lab-setup-guide.md).
2. On `db-vm`: load `db/01_schema.sql`, `db/02_seed.sql`, `db/03_app_account_INSECURE.sql`.
3. On `app-vm`: deploy `app/vulnerable/`.
4. From `kali-vm`: run `guides/01-attack-guide.md` → capture the "before" evidence.
5. Apply defenses (`db/04`→`db/09`, deploy `app/secure/`) and re-run the attacks → capture the "after" evidence.
6. Backup/recovery (Phase 8), incident investigation (Phase 10), then compile `report/`.

## v2 — Security deepening (attack/defense round 2)

A second hardening round builds on the verified v1 base. All v2 controls are tested end-to-end (see `VERIFICATION.md`, and `docs/phase11`–`phase15`):

| Area | v2 upgrade | Files |
|------|-----------|-------|
| Authentication | server-side **pepper**, **TOTP MFA**, anti-DoS **per-IP throttling**, session hardening | `db/10_auth_hardening.sql`, `app/secure/{password,totp,ratelimit,login_flow,security_bootstrap}.php` |
| Access control | **Row-Level Security** in the DB (DEFINER view + `@app_patient_id`) | `db/13_rls.sql` |
| Crypto | **blind index** (searchable encryption: exact search + uniqueness over AES data) | `db/11_blind_index.sql`, `app/secure/searchable.php` |
| Audit | **tamper-evident hash chain** (detects DBA deletion/modification) | `db/12_audit_chain.sql` |
| Injection | **second-order** + **blind/time-based** re-attack → neutralized | (tested; `docs/phase15`) |
| Transport | **mutual TLS** (client certificate, `REQUIRE X509`) | `db/14_hardening_plus.sql` |
| DoS | **resource limits** per account, `skip_show_database` | `db/14_hardening_plus.sql` |

**Consolidated re-attack:** all v2 defenses stacked and every attack replayed → 7/7 blocked.
