-- =====================================================================
--  Phase 6 — Sensitive data protection (encryption at rest)
--  Converts the most sensitive columns to VARBINARY so the application can
--  store AES-256-GCM ciphertext. Run AFTER data exists; then run the PHP
--  migration app/secure/encrypt_sensitive.php to replace plaintext with
--  ciphertext. (The old plaintext survives the type change as raw bytes,
--  which the migration reads once and overwrites.)
--
--  Why these columns (data classification, Phase 1):
--    patients.national_id        — Restricted (national identification)
--    billing.insurance_policy_no — Confidential (financial/insurance)
--    medical_records.clinical_notes — Restricted (PHI free text)
--  Passwords are NOT encrypted — they are one-way hashed (Argon2id, Phase 3).
-- =====================================================================
USE hospital;

ALTER TABLE patients        MODIFY national_id        VARBINARY(128)  NULL;
ALTER TABLE billing         MODIFY insurance_policy_no VARBINARY(128)  NULL;
ALTER TABLE medical_records MODIFY clinical_notes      VARBINARY(4096) NULL;

-- The UNIQUE key on the (now encrypted) national_id is dropped: GCM uses a
-- random IV per row, so equal plaintexts yield different ciphertexts and a
-- uniqueness constraint is no longer meaningful. Uniqueness is enforced in
-- the application before insert (lookup by deterministic hash if required).
ALTER TABLE patients DROP INDEX uq_patient_national;

-- TLS in transit: require encrypted connections for the app account
-- (certificates generated on db-vm — see docs/phase6-sensitive-data.md).
ALTER USER 'app_svc'@'192.168.56.20' REQUIRE SSL;
