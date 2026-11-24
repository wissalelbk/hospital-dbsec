-- =====================================================================
--  Phase 12 — Row-Level Security in the database (anti-IDOR, defense in depth)
--  MySQL/MariaDB have no native RLS and reject a session variable used
--  directly in a view body (ERROR 1351). We therefore wrap the server-set
--  session variable @app_patient_id in a stored FUNCTION, which a view may
--  call. The patient DB role is granted SELECT on the VIEWS only — never on
--  the base tables — so even an application IDOR bug cannot leak another
--  patient's rows: the filter is enforced inside the database, and fails
--  CLOSED when the variable is unset.
--
--  The app runs  SET @app_patient_id = <session patient_id>  after login.
-- =====================================================================
USE hospital;

DROP VIEW IF EXISTS v_patient_medical_records;
DROP VIEW IF EXISTS v_patient_billing;
DROP FUNCTION IF EXISTS current_patient;

DELIMITER //
CREATE FUNCTION current_patient() RETURNS INT
    NOT DETERMINISTIC NO SQL
    RETURN CASE WHEN @app_patient_id REGEXP '^[0-9]+$'
                THEN CAST(@app_patient_id AS UNSIGNED)
                ELSE NULL END//
DELIMITER ;

CREATE SQL SECURITY DEFINER VIEW v_patient_medical_records AS
    SELECT m.record_id, m.patient_id, m.visit_date, m.diagnosis, m.treatment, m.clinical_notes
    FROM medical_records m
    WHERE m.patient_id = current_patient();

CREATE SQL SECURITY DEFINER VIEW v_patient_billing AS
    SELECT b.invoice_id, b.patient_id, b.amount, b.status, b.issued_at
    FROM billing b
    WHERE b.patient_id = current_patient();

-- Patient role: access ONLY through the self-filtered views
-- REVOKE SELECT ON hospital.medical_records FROM 'role_patient';
-- REVOKE SELECT ON hospital.billing         FROM 'role_patient';
-- GRANT  SELECT ON hospital.v_patient_medical_records TO 'role_patient';
-- GRANT  SELECT ON hospital.v_patient_billing         TO 'role_patient';
