# Phase 19 (v3) — Audit notarization (closing the DBA-recompute gap)

Deepens Phases 7/14. Files: `db/18_audit_notary.sql`, `app/secure/notary.php`.

## The remaining gap
The hash chain (Phase 14) detects naive tampering, but a **DBA who knows the scheme** could delete a row and **recompute the entire chain** (`sp_recompute_chain`) to restore internal consistency — `verify_audit_chain()` would then pass.

## Defense
The application periodically **notarizes** the current chain tip: it signs `(upto_log_id ‖ row_hash)` with an **offline audit key** (`HMAC-SHA256`) and stores the signature in `audit_notary`. A DBA cannot forge a signature for a new tip without that key, so any change to already-notarized history is detected.

## Verified (3/3)
1. After notarization, `verify_notary()` → **intact**.
2. A DBA **deletes a row and recomputes the whole chain** → `verify_audit_chain()` now **passes** (internal consistency restored).
3. **But** `verify_notary()` → **"chain tip changed since notarization"** — the tampering is detected, because the recomputed tip no longer matches the signed value and the DBA cannot re-sign.

## Operational notes
Notarize on a short schedule (e.g. every few minutes) and also **ship audit rows off-host** (append-only/SIEM) so the on-host copy is not the sole record. Together, the chain + notary + off-host shipping give tamper-evidence against insiders up to and including the DBA.
