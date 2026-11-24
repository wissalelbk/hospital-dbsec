# Phase 6 — Sensitive Data Protection

Hospital Patient Records System — UIR ESIN ING5, Database Security (Dr. Harazeem)
Implementation: `db/06_sensitive_data.sql`, `app/secure/crypto.php`, `app/secure/encrypt_sensitive.php`

---

## 1. Plaintext vs Encryption vs Hashing vs Secure password hashing

The brief requires that the team can explain these clearly:

| Concept | Reversible? | Use here | Why |
|---------|-------------|----------|-----|
| **Plaintext storage** | — | ❌ never for sensitive data | Anyone reading the table (or a dump/backup) sees the value |
| **Encryption** (e.g. AES-256-GCM) | Yes, *with the key* | national_id, insurance_policy_no, clinical_notes | Values must be **recovered** for display, but unreadable to anyone without the key |
| **Hashing** (e.g. SHA-256) | No | not for passwords alone | Fast hashes are brute-forceable and unsalted → unsuitable for passwords |
| **Secure password hashing** (Argon2id) | No (one-way) | `app_users.password_hash` | Passwords never need recovery; Argon2id is salted, slow and memory-hard, resisting GPU/ASIC cracking |

Key idea: **passwords are hashed (one-way)** because we only ever need to *verify* them; **identifiers and clinical notes are encrypted (reversible)** because the app must *display* them to authorized users.

---

## 2. What is protected and why (from the Phase 1 classification)

| Column | Class | Mechanism |
|--------|-------|-----------|
| `app_users.password_hash` | Restricted (secret) | Argon2id (Phase 3) — one-way |
| `patients.national_id` | Restricted (national ID) | AES-256-GCM at rest |
| `medical_records.clinical_notes` | Restricted (PHI) | AES-256-GCM at rest |
| `billing.insurance_policy_no` | Confidential (financial) | AES-256-GCM at rest |
| All sensitive data **in transit** | — | TLS between app-vm and db-vm |

AES-256-**GCM** is chosen because it is *authenticated* encryption: it provides confidentiality **and** tamper detection (a modified ciphertext fails to decrypt).

---

## 3. Data at rest — implementation

- Columns converted to `VARBINARY` (`db/06_sensitive_data.sql`).
- The application encrypts before insert and decrypts for display (`crypto.php`), layout per value: `[12-byte IV][16-byte GCM tag][ciphertext]`.
- The `UNIQUE` index on `national_id` was dropped: a random IV per row makes equal plaintexts encrypt differently, so SQL uniqueness is no longer meaningful; uniqueness is enforced in the application.

## 4. Key management (justified)

- 32-byte AES key stored **outside the database and outside the code**, in `/etc/hospital/app.key`, `chmod 600`, owned by the web user.
  ```bash
  mkdir -p /etc/hospital
  head -c 32 /dev/urandom > /etc/hospital/app.key
  chmod 600 /etc/hospital/app.key && chown www-data /etc/hospital/app.key
  ```
- Path supplied via `APP_KEY_FILE`; never committed to source control.
- **Rotation:** decrypt-with-old → re-encrypt-with-new in a maintenance job; GCM tags make a wrong/old key or tampering fail safe (returns null).
- **Separation:** because the key lives on app-vm (not db-vm), a dump of the database alone — e.g. via SQL injection or a stolen backup — yields only ciphertext.

## 5. Data in transit — TLS

- `app_svc` is declared `REQUIRE SSL`, so the DB refuses plaintext connections from the app.
- Certificates generated on db-vm (lab CA); the app verifies the server certificate (`MYSQL_ATTR_SSL_VERIFY_SERVER_CERT = true`).
  ```bash
  # on db-vm (self-signed lab CA)
  mysql_ssl_rsa_setup --datadir=/var/lib/mysql
  ```

---

## 6. Verification — Before / After (tested)

| Observation | Baseline | Hardened |
|-------------|----------|----------|
| `SELECT national_id FROM patients` (attacker dump) | `AA112233` (readable) | `0x5358A2A9EB43…` — **36 bytes ciphertext** |
| App display for authorized user | readable | readable (decrypted in app: `AA112233`) |
| Dumped password | `Admin@123` (cleartext) | `$argon2id$v=19$m=65536,t=3,p=1$…` (uncrackable hash) |
| Tampered ciphertext byte | — | decryption returns **null** (GCM detected tampering) |

**Conclusion:** after remediation, a successful table dump (via any residual injection or a stolen backup) returns only authenticated ciphertext and Argon2id hashes — the sensitive information is no longer exposed, satisfying the confidentiality requirement from the CIA analysis.
