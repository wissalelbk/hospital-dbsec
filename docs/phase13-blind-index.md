# Phase 13 (v2) — Searchable encryption via blind index

Deepens Phase 6. Files: `db/11_blind_index.sql`, `app/secure/searchable.php`.

## Problem
Randomized AES-GCM (Phase 6) protects `national_id` at rest, but a random IV per row means equal national_ids encrypt differently — so we lost **exact-match lookup** and the **UNIQUE constraint** (the Phase 6 migration had to drop `uq_patient_national`).

## Defense — a keyed blind index
Store, next to the ciphertext, a deterministic keyed hash:

```
national_id_bidx = HMAC-SHA256( bidx_key , normalize(national_id) )   -- BINARY(32), UNIQUE
```

- **Deterministic** → equal national_ids yield equal bidx → a `UNIQUE` index re-enforces uniqueness over encrypted data.
- **Exact-match search** → compute the query's bidx and filter `WHERE national_id_bidx = ?`.
- **Keyed + one-way** → the index leaks neither the plaintext nor equality to anyone without the key. The blind-index key is **separate** from the AES key (key separation).

## Verified (5/5)
- Ciphertext stays **randomized** (two encryptions of the same id differ).
- Exact-match search by national_id returns the right patient and decrypts correctly.
- Search is **case/space-insensitive** (normalization).
- A **duplicate** national_id insert is **rejected** by the UNIQUE blind index.
- The stored blind index is a 32-byte HMAC that does **not** contain the plaintext.

> Trade-off: a blind index supports equality (and, with tokenization, prefix) lookups — not range queries. For `national_id` (looked up by exact value) this is exactly what is needed.
