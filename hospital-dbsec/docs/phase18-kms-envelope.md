# Phase 18 (v3) — Envelope encryption & key management

Deepens Phase 6 ("key management principles"). Files: `db/17_kms.sql`, `app/secure/kms.php`.

## Two-tier keys
- **KEK** (Key-Encryption-Key): a master key kept **offline** in a file.
- **DEK** (Data-Encryption-Key): a random key that actually encrypts data; stored **wrapped** (AES-GCM under the KEK) in `crypto_keys`, with a **version**.

Every ciphertext is self-describing: `[version:1][IV:12][tag:16][ciphertext]`, so the right DEK version is selected automatically on decrypt.

## Why this is better than a single static key
- **KEK rotation** (e.g. after a suspected exposure or on a schedule) only **re-wraps the DEK** — **no data is re-encrypted**. Cheap and fast, even for millions of rows.
- **DEK rotation** issues a new versioned DEK for new data; old data keeps decrypting via its version tag, and can be lazily re-encrypted over time.
- Compromise of the database alone yields only **wrapped** DEKs — useless without the offline KEK.

## Verified (8/8)
- Envelope encrypt/decrypt round-trip (version tag = 1).
- **KEK rotation**: the stored wrapped DEK changes, yet data encrypted *before* rotation still decrypts — confirming no data re-encryption was needed.
- **DEK rotation**: new active version = 2; new data is tagged v2; old v1 data still decrypts; v2 data decrypts.

This maps directly to how a real KMS/HSM (AWS KMS, Vault) manages data keys, and is the production-grade answer to the Phase 6 key-management requirement.
