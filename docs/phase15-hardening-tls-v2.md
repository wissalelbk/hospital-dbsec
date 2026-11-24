# Phase 15 (v2) — Second-order/blind SQLi, mutual TLS, resource limits, CVE re-check

Files: `db/14_hardening_plus.sql`, PKI under `mdb/ssl/` (lab).

## 1. Second-order & blind SQL injection (re-attack)
Beyond classic injection, two harder variants were re-attacked against the secure code:

- **Blind / time-based**: a payload `' OR IF(1=1,SLEEP(1),0)-- -`. On the **concatenated** (vulnerable) query it executed — **8002 ms** (SLEEP fired per row); on the **prepared** query it was inert — **0 ms**.
- **Second-order** (stored then reused): a SLEEP payload was stored as a patient's `last_name` via a prepared statement (inert data), then reused by a "report" sink. The **concatenated** sink triggered the stored payload — **4001 ms**; the **prepared** sink stayed inert — **0 ms**.

Conclusion: parameterization neutralizes injection **wherever** the value originates — live input or previously-stored data. (5/5 tested.)

## 2. Mutual TLS (client certificates)
Beyond server-side TLS, the application account now authenticates with a **client certificate** (`REQUIRE X509`). A lab PKI (CA → server cert → client cert) was generated and MariaDB restarted with TLS.

Verified (3/3) against a live TLS server:
- Connection **with** the client certificate → **accepted**.
- Connection **without** the client certificate (TLS only) → **`ERROR 1045 Access denied`** (X509 required).
- Negotiated cipher: **`TLS_AES_256_GCM_SHA384`** (TLS 1.3).

This means a stolen password alone no longer grants DB access — the attacker also needs the client key.

## 3. Resource limits (anti-DoS at the DBMS)
`app_svc` is capped with `MAX_USER_CONNECTIONS 20`, `MAX_QUERIES_PER_HOUR 50000`, `MAX_UPDATES_PER_HOUR 20000`, so a runaway or abused account cannot exhaust the server. Verified: the limits are stored and enforced on the account (`2/100` on a test account). Plus `skip_show_database`, `max_connect_errors` and `tls_version=TLSv1.2,TLSv1.3` in the config.

## 4. CVE re-check (2026-11-13)
Re-verified against current advisories: the **Oracle Critical Patch Update of October 2026** (dev.mysql.com advisory 2026-10-20) remains the **latest** quarterly; the next is January 2027. **CVE-2026-101800** (Server: Security: Privileges) is confirmed at **CVSS 6.8**, affecting MySQL Server 8.4.0–8.4.12 (fixed in **8.4.13**) — our least-privilege design already blunts this privilege-escalation class. No newer advisory has appeared since the v1 report.
