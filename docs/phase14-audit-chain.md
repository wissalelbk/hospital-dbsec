# Phase 14 (v2) — Tamper-evident audit log (hash chain)

Deepens Phase 7. File: `db/12_audit_chain.sql`.

## Problem
In v1 the audit log is append-only **for the application account**, but a **DBA** (or an attacker who reaches DBA) can still delete or alter audit rows to cover their tracks.

## Defense — chain each row to the previous one
A `BEFORE INSERT` trigger computes, for every audit row:

```
row_hash = SHA256( prev_hash || event_time || username || action || resource || resource_id || success || ip )
```

where `prev_hash` is the previous row's `row_hash` (zeros for the first row). Deleting, modifying or reordering **any** row makes the stored hashes inconsistent with the recomputed chain. The `verify_audit_chain()` procedure recompiles the chain with a window function and returns the **first** row where it breaks.

## Verified
- **Intact chain** → `verify_audit_chain()` returns no rows.
- **Modification** (a DBA rewrites an `ACCOUNT_CHANGE` into `LOGIN_SUCCESS`) → detected at that `log_id`.
- **Deletion** (a DBA removes a middle row) → detected (the following row's `prev_hash` no longer matches).

## Note on wholesale recomputation
A DBA who understands the scheme could, in principle, recompute the whole downstream chain after tampering. Two measures close this:
1. **App-side notarization**: periodically the application HMACs the latest `row_hash` with an **offline audit key** and stores/exports the signature; recomputation without that key is detectable.
2. **Off-host shipping**: audit rows are also streamed to append-only storage (e.g. a SIEM), so the on-host copy is not the only record.

A concurrency note: the chain assumes serialized inserts (true for the app's audit writer); under heavy concurrent writers a short table lock or a single-writer queue preserves ordering.
