# Phase 11 (v2) — Authentication hardening in depth

Deepens Phase 3. Files: `db/10_auth_hardening.sql`, `app/secure/{password,totp,ratelimit,security_bootstrap,login_flow}.php`.

---

## 1. Server-side pepper on top of Argon2id

**Threat.** If the database leaks (SQLi, stolen backup), an attacker runs an offline Argon2id crack against the hashes.

**Defense.** A 32-byte **pepper** kept outside the DB (like the AES key) is mixed in before hashing: `Argon2id( HMAC-SHA256(pepper, password) )`. Without the pepper — which never leaves the app host — the leaked hashes cannot be cracked.

**Verified:** a v2 hash validates the correct password through `verify_password()`, but a plain `password_verify()` of the real password against the stored hash **fails** — proving the hash is useless to anyone who stole only the database.

Hashes are **versioned** (`hash_version`): legacy v1 (no pepper) still verify and are transparently upgraded to v2.

## 2. MFA — TOTP (RFC 6238) for privileged accounts

Time-based one-time passwords (HMAC-SHA1, 30 s, 6 digits), compatible with Google Authenticator / Aegis / FreeOTP. The per-user secret is stored **AES-GCM encrypted**. Privileged accounts set `mfa_enabled = 1`; login then requires a valid code after the password stage.

**Verified against the official RFC 6238 test vectors:** secret `GEZD…` yields `287082` at T=59 and `081804` at T=1111111109 — exact match. A full cycle (generate → encrypt → store → read → decrypt → verify current code) passes; a wrong code is rejected.

## 3. Anti-DoS login throttling

**Threat.** A naive per-account lockout lets an attacker **deny service to a victim** by deliberately failing their username until it locks.

**Defense.** The primary brake is **per-IP** (`login_throttle` table): an attacker flooding from one host is blocked by IP and cannot lock a victim out. A much softer per-account counter is secondary.

**Verified:** after 5 failures from `192.168.56.30` that IP is throttled, while a legitimate user authenticating for the **same account from a different IP** is still served — no lockout-DoS.

## 4. Session hardening

`secure_session_start()` sets cookies `HttpOnly` (anti-XSS theft), `Secure` (TLS-only), `SameSite=Strict` (anti-CSRF), renames the session, and enforces an **8 h absolute** + **20 min idle** timeout. `send_security_headers()` adds CSP, HSTS, `X-Frame-Options: DENY`, `nosniff`, `Referrer-Policy`, `Permissions-Policy`.

## 5. Unified flow (`login_flow.php`)

Order: **IP throttle → prepared-statement lookup → pepper+Argon2id verify → TOTP gate → reset brakes + audit**. End-to-end verification (8/8): direct login without MFA, wrong password rejected, MFA gate (`mfa_required` → correct code OK, wrong code fail), SQLi payload neutralized, attacker IP throttled while a legitimate IP is unaffected. The audit calls fail safe (the app keeps working even if the audit table is unavailable).
