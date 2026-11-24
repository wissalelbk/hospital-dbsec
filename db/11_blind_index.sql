-- =====================================================================
--  Phase 13 — Blind index for searchable encryption of national_id
--  Restores exact-match search + uniqueness over the AES-encrypted column.
-- =====================================================================
USE hospital;

ALTER TABLE patients
    ADD COLUMN national_id_bidx BINARY(32) NULL AFTER national_id,
    ADD UNIQUE KEY uq_patient_bidx (national_id_bidx);

-- The application computes national_id_bidx = HMAC-SHA256(bidx_key, normalize(id))
-- on insert/update, and looks patients up with:
--     SELECT ... FROM patients WHERE national_id_bidx = ?   (bound bidx)
-- The UNIQUE key now rejects duplicate national_ids even though each
-- national_id ciphertext is randomized (different IV per row).
