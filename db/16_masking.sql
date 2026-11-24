-- =====================================================================
--  Phase 17 (v3) — Dynamic data masking by role
--  A single view redacts PII differently depending on the caller's role
--  (server-set @app_role), so a lower-privileged role sees masked values
--  while an authorized clinician sees them in clear. Complements RBAC
--  (who can read the row) with field-level minimization (what they see).
-- =====================================================================
USE hospital;

DROP VIEW IF EXISTS v_patients_masked;
DROP FUNCTION IF EXISTS app_role;

DELIMITER //
CREATE FUNCTION app_role() RETURNS VARCHAR(50) NOT DETERMINISTIC NO SQL
    RETURN COALESCE(@app_role,'')//
DELIMITER ;

CREATE SQL SECURITY DEFINER VIEW v_patients_masked AS
SELECT patient_id, first_name, last_name,
    CASE WHEN app_role() IN ('DBA','Doctor','Nurse') THEN phone
         ELSE CONCAT('******', RIGHT(phone,2)) END                          AS phone,
    CASE WHEN app_role() IN ('DBA','Doctor') THEN CAST(date_of_birth AS CHAR)
         ELSE CONCAT(YEAR(date_of_birth),'-**-**') END                      AS date_of_birth,
    CASE WHEN app_role() IN ('DBA','Doctor','Nurse') THEN address
         ELSE CONCAT(LEFT(address,4),'…') END                              AS address,
    blood_type
FROM patients;
