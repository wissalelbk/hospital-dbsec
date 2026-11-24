# Phase 9 — Database Hardening

Hospital Patient Records System — UIR ESIN ING5, Database Security (Dr. Harazeem)
Implementation: `db/09_hardening.sql`, config notes, firewall rules. CVE context: `docs/cve-reference.md`.

---

## 1. Before / After hardening assessment

| Security issue | Before hardening | After hardening | Justification |
|----------------|------------------|-----------------|---------------|
| Anonymous DB accounts | **2 present** (`''@localhost`, `''@vm`) | **0** (removed) | Anonymous accounts allow unauthenticated local access |
| Sample `test` database | **present** + 2 `PUBLIC` grants on `test`/`test\_%` | **removed**, 0 grants | Default DB with world-writable grants is a foothold |
| Application DB account | `root@%` / `app@%` **ALL PRIVILEGES** | dropped → `app_svc` least-privilege (6 tables) | Bounds SQLi blast radius; counters priv-esc (CVE-2026-101800) |
| Shared / network root | `root@192.168.56.20` reachable | removed; root localhost-only | No remote super-user |
| Password storage | plaintext | Argon2id (`m=64MiB,t=3,p=1`) | OWASP 2026 |
| SQL injection | exploitable | prepared statements | Closes the injection |
| Sensitive data at rest | cleartext | AES-256-GCM | Dump returns ciphertext |
| Data in transit | plaintext | TLS, `require_secure_transport=ON`, `REQUIRE SSL` | Counters bundled-OpenSSL exposure surface (CVE-2025-15467) |
| X Plugin (port 33060) | enabled, exposed to lab | disabled (`UNINSTALL PLUGIN mysqlx` / `mysqlx=OFF`) | Removes RCE surface (CVE-2026-60316) |
| Replication components | — (unused) | not enabled | Removes priv-esc surface (CVE-2026-60163/60332/60585/101781) |
| `local_infile` | ON | OFF | Blocks LOAD DATA LOCAL abuse |
| Network exposure | `bind-address=0.0.0.0`, no firewall | bound to lab NIC; `ufw` allows 3306 only from app-vm | DB no longer reachable from kali-vm |
| Password policy | none | `validate_password` STRONG, len ≥ 12 | Resists weak credentials / brute force |
| Audit logging | disabled / none | audit tables + triggers (Phase 7) | Traceability |
| Backups | none | tested dump + PITR, restricted perms | Recoverability (Phase 8) |
| Patch status | unverified | patched 8.4.x LTS per Oct 2026 CPU | Closes the 98 MySQL CVEs incl. the 9.8 flaws |

## 2. Network exposure — before/after (re-tested from kali-vm)

| Check from kali-vm (192.168.56.30) | Before | After |
|------------------------------------|--------|-------|
| `nmap 3306` on db-vm | `open` | `filtered` (firewall: only app-vm allowed) |
| `nmap 33060` (X Plugin) | `open` | `closed` (plugin disabled) |
| `mysql -h 192.168.56.10 -uroot -proot` | connects | refused (no network root; TLS required) |

## 3. Patch/update status (CVE-driven)

Record `SELECT VERSION();` on db-vm and confirm it is a build that includes the **October 2026 CPU** fixes (98 MySQL patches). The two 9.8 flaws this cycle — **CVE-2025-15467** (OpenSSL) and **CVE-2026-9547** (curl) — are in bundled libraries, so patch currency is the control. See `docs/cve-reference.md` for the mapping and re-check procedure.

## 4. Justification of each major decision

- **Remove defaults / anonymous / test DB** — eliminates unauthenticated footholds (tested: 2 anon accounts + test DB removed).
- **Least privilege** — the single most impactful control: it converts "SQLi = full DBMS takeover" into "SQLi = bounded read/write on six tables", and it is exactly what blunts privilege-escalation CVEs like CVE-2026-101800.
- **Disable unused features (X Plugin, replication)** — you cannot be exploited through a feature you don't run; this directly removes the components behind several July/October 2026 CVEs.
- **Force TLS + patch the crypto stack** — protects data in transit and closes the pre-auth OpenSSL surface.
- **Network segmentation** — the database should only ever be reachable from the application server, never from a user workstation (or an attacker's).
