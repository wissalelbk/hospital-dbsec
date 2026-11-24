-- =====================================================================
--  Phase 16 (v3) — Stored-procedure API (query allow-listing)
--  The application account loses ALL direct table privileges and is granted
--  EXECUTE on a small, fixed set of parameterized procedures only. The
--  attack surface collapses to the procedure signatures: even a fully
--  compromised application (or a residual SQL-injection) cannot run
--  arbitrary SQL — it can only invoke the allow-listed operations, with
--  typed, bound parameters. Procedures are SQL SECURITY DEFINER, so they
--  run with the owner's table rights while the caller has none.
-- =====================================================================
USE hospital;

DROP PROCEDURE IF EXISTS sp_login_lookup;
DROP PROCEDURE IF EXISTS sp_find_patient;
DROP PROCEDURE IF EXISTS sp_list_records;
DROP PROCEDURE IF EXISTS sp_add_record;
DROP PROCEDURE IF EXISTS sp_update_billing_status;
DROP PROCEDURE IF EXISTS sp_audit_write;

DELIMITER //

-- Auth lookup (the app never selects app_users directly)
CREATE DEFINER=root@localhost PROCEDURE sp_login_lookup(IN p_username VARCHAR(64))
    SQL SECURITY DEFINER
BEGIN
    SELECT u.user_id, u.username, u.password_hash, u.hash_version, u.mfa_enabled,
           u.totp_secret, u.role_id, r.role_name, u.is_active, u.staff_id, u.patient_id
    FROM app_users u JOIN roles r ON r.role_id = u.role_id
    WHERE u.username = p_username;
END//

-- Exact-match patient lookup by blind index (no raw table access)
CREATE DEFINER=root@localhost PROCEDURE sp_find_patient(IN p_bidx BINARY(32))
    SQL SECURITY DEFINER
BEGIN
    SELECT patient_id, national_id, first_name, last_name, date_of_birth, phone, blood_type
    FROM patients WHERE national_id_bidx = p_bidx;
END//

-- A patient's medical records (row scope passed explicitly, bound)
CREATE DEFINER=root@localhost PROCEDURE sp_list_records(IN p_patient_id INT)
    SQL SECURITY DEFINER
BEGIN
    SELECT record_id, patient_id, visit_date, diagnosis, treatment, clinical_notes
    FROM medical_records WHERE patient_id = p_patient_id ORDER BY visit_date DESC;
END//

-- Insert a record (all values bound)
CREATE DEFINER=root@localhost PROCEDURE sp_add_record(
    IN p_patient INT, IN p_doctor INT, IN p_diag VARCHAR(255), IN p_treat TEXT, IN p_notes VARBINARY(4096))
    SQL SECURITY DEFINER
BEGIN
    INSERT INTO medical_records (patient_id, doctor_staff_id, visit_date, diagnosis, treatment, clinical_notes)
    VALUES (p_patient, p_doctor, NOW(), p_diag, p_treat, p_notes);
END//

-- Update a billing status (constrained set)
CREATE DEFINER=root@localhost PROCEDURE sp_update_billing_status(IN p_invoice INT, IN p_status VARCHAR(16))
    SQL SECURITY DEFINER
BEGIN
    UPDATE billing SET status = p_status WHERE invoice_id = p_invoice;
END//

-- Append-only audit write
CREATE DEFINER=root@localhost PROCEDURE sp_audit_write(
    IN p_uid INT, IN p_user VARCHAR(64), IN p_action VARCHAR(40),
    IN p_res VARCHAR(64), IN p_resid VARCHAR(64), IN p_ok TINYINT, IN p_ip VARCHAR(45))
    SQL SECURITY DEFINER
BEGIN
    INSERT INTO audit_log (app_user_id, username, action, resource, resource_id, success, ip_address)
    VALUES (p_uid, p_user, p_action, p_res, p_resid, p_ok, p_ip);
END//

DELIMITER ;

-- ---------------------------------------------------------------------
-- The application account: EXECUTE on the API only — NO table privileges
-- ---------------------------------------------------------------------
-- (production account)
-- CREATE USER 'app_api'@'192.168.56.20' IDENTIFIED BY '...' REQUIRE X509;
-- GRANT EXECUTE ON PROCEDURE hospital.sp_login_lookup          TO 'app_api'@'192.168.56.20';
-- GRANT EXECUTE ON PROCEDURE hospital.sp_find_patient          TO 'app_api'@'192.168.56.20';
-- GRANT EXECUTE ON PROCEDURE hospital.sp_list_records          TO 'app_api'@'192.168.56.20';
-- GRANT EXECUTE ON PROCEDURE hospital.sp_add_record            TO 'app_api'@'192.168.56.20';
-- GRANT EXECUTE ON PROCEDURE hospital.sp_update_billing_status TO 'app_api'@'192.168.56.20';
-- GRANT EXECUTE ON PROCEDURE hospital.sp_audit_write           TO 'app_api'@'192.168.56.20';
-- (NO GRANT SELECT/INSERT/UPDATE on any table.)
