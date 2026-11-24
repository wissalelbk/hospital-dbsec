-- =====================================================================
--  Phase 2 — RBAC, database roles & LEAST PRIVILEGE  (SECURE / "AFTER")
--  Engine: MySQL 8.4 LTS
--
--  This script replaces the insecure baseline (db/03_app_account_INSECURE.sql):
--    * removes the over-privileged root@192.168.56.20 and app@% accounts
--    * creates one DB role per job function with minimal grants
--    * creates per-role demonstration users (for privilege testing)
--    * creates a LEAST-PRIVILEGE application service account (app_svc)
--
--  Principle of Least Privilege is the goal: even if the application is
--  injected, the blast radius is bounded to the hospital data tables,
--  read/write only — no DDL, no DROP, no mysql.*, no FILE, no GRANT.
-- =====================================================================
USE hospital;

-- ---------------------------------------------------------------------
-- 0. Remove the insecure baseline accounts (REVOKE + DROP)
-- ---------------------------------------------------------------------
DROP USER IF EXISTS 'root'@'192.168.56.20';
DROP USER IF EXISTS 'app'@'%';

-- ---------------------------------------------------------------------
-- 1. Create roles (one per job function)
-- ---------------------------------------------------------------------
CREATE ROLE IF NOT EXISTS
    'role_dba', 'role_doctor', 'role_nurse',
    'role_receptionist', 'role_accountant', 'role_patient';

-- ---- DBA: full control of the hospital schema only (not *.*) ----
GRANT ALL PRIVILEGES ON hospital.* TO 'role_dba';

-- ---- Doctor: full clinical access, NO billing, NO user table, NO delete ----
GRANT SELECT, INSERT, UPDATE ON hospital.medical_records TO 'role_doctor';
GRANT SELECT, INSERT, UPDATE ON hospital.prescriptions   TO 'role_doctor';
GRANT SELECT, INSERT, UPDATE ON hospital.lab_results      TO 'role_doctor';
GRANT SELECT, INSERT, UPDATE ON hospital.appointments     TO 'role_doctor';
GRANT SELECT                  ON hospital.patients         TO 'role_doctor';
GRANT SELECT                  ON hospital.staff            TO 'role_doctor';

-- ---- Nurse: read clinical data, update appointments only ----
GRANT SELECT ON hospital.patients        TO 'role_nurse';
GRANT SELECT ON hospital.medical_records TO 'role_nurse';
GRANT SELECT ON hospital.prescriptions   TO 'role_nurse';
GRANT SELECT ON hospital.lab_results     TO 'role_nurse';
GRANT SELECT, UPDATE ON hospital.appointments TO 'role_nurse';

-- ---- Receptionist: demographics + scheduling ONLY (no clinical, no billing) ----
GRANT SELECT, INSERT, UPDATE ON hospital.patients     TO 'role_receptionist';
GRANT SELECT, INSERT, UPDATE ON hospital.appointments TO 'role_receptionist';
GRANT SELECT                  ON hospital.staff        TO 'role_receptionist';

-- ---- Accountant: billing ONLY + minimal patient identity (via a view) ----
GRANT SELECT, INSERT, UPDATE ON hospital.billing TO 'role_accountant';

-- ---- Patient: read-only on own clinical/billing data (row filtering in app) ----
GRANT SELECT ON hospital.medical_records TO 'role_patient';
GRANT SELECT ON hospital.prescriptions   TO 'role_patient';
GRANT SELECT ON hospital.lab_results     TO 'role_patient';
GRANT SELECT ON hospital.appointments    TO 'role_patient';
GRANT SELECT ON hospital.billing         TO 'role_patient';

-- Minimal-identity view for accountants (name only, no national_id/clinical)
CREATE OR REPLACE VIEW v_patient_identity AS
    SELECT patient_id, first_name, last_name FROM patients;
GRANT SELECT ON hospital.v_patient_identity TO 'role_accountant';

-- ---------------------------------------------------------------------
-- 2. Per-role demonstration users (for RBAC + privilege testing evidence)
--    (strong passwords; connect from the app server subnet)
-- ---------------------------------------------------------------------
CREATE USER IF NOT EXISTS 'dba_user'@'192.168.56.%'    IDENTIFIED BY 'Dba#Str0ng!2026';
CREATE USER IF NOT EXISTS 'doctor_user'@'192.168.56.%' IDENTIFIED BY 'Doc#Str0ng!2026';
CREATE USER IF NOT EXISTS 'nurse_user'@'192.168.56.%'  IDENTIFIED BY 'Nur#Str0ng!2026';
CREATE USER IF NOT EXISTS 'recep_user'@'192.168.56.%'  IDENTIFIED BY 'Rec#Str0ng!2026';
CREATE USER IF NOT EXISTS 'acct_user'@'192.168.56.%'   IDENTIFIED BY 'Acc#Str0ng!2026';

GRANT 'role_dba'          TO 'dba_user'@'192.168.56.%';
GRANT 'role_doctor'       TO 'doctor_user'@'192.168.56.%';
GRANT 'role_nurse'        TO 'nurse_user'@'192.168.56.%';
GRANT 'role_receptionist' TO 'recep_user'@'192.168.56.%';
GRANT 'role_accountant'   TO 'acct_user'@'192.168.56.%';

-- Activate the granted role automatically at login
SET DEFAULT ROLE ALL TO
    'dba_user'@'192.168.56.%', 'doctor_user'@'192.168.56.%',
    'nurse_user'@'192.168.56.%', 'recep_user'@'192.168.56.%',
    'acct_user'@'192.168.56.%';

-- ---------------------------------------------------------------------
-- 3. LEAST-PRIVILEGE application service account
--    The web app connects as THIS account (not root). It can do only the
--    DML the application needs — scoped to the hospital schema.
-- ---------------------------------------------------------------------
CREATE USER IF NOT EXISTS 'app_svc'@'192.168.56.20'
    IDENTIFIED BY 'App$vc#Change!2026'
    REQUIRE SSL;                         -- force TLS in transit (Phase 6)

-- Only the tables/operations the app performs on behalf of authenticated users:
GRANT SELECT, INSERT, UPDATE ON hospital.patients        TO 'app_svc'@'192.168.56.20';
GRANT SELECT, INSERT, UPDATE ON hospital.medical_records TO 'app_svc'@'192.168.56.20';
GRANT SELECT, INSERT, UPDATE ON hospital.prescriptions   TO 'app_svc'@'192.168.56.20';
GRANT SELECT, INSERT, UPDATE ON hospital.lab_results     TO 'app_svc'@'192.168.56.20';
GRANT SELECT, INSERT, UPDATE ON hospital.appointments    TO 'app_svc'@'192.168.56.20';
GRANT SELECT, INSERT, UPDATE ON hospital.billing         TO 'app_svc'@'192.168.56.20';
GRANT SELECT                  ON hospital.roles           TO 'app_svc'@'192.168.56.20';
GRANT SELECT                  ON hospital.staff           TO 'app_svc'@'192.168.56.20';
-- login needs to read hashes and update lockout/last_login:
GRANT SELECT, UPDATE          ON hospital.app_users       TO 'app_svc'@'192.168.56.20';
-- audit log is append-only for the app (INSERT only — cannot erase its tracks):
-- (table created in db/07_audit.sql)
-- GRANT INSERT ON hospital.audit_log TO 'app_svc'@'192.168.56.20';

-- Explicitly NOT granted: DROP, ALTER, DELETE, CREATE USER, FILE,
-- GRANT OPTION, and ANY access to the mysql.* system schema.

FLUSH PRIVILEGES;

-- ---------------------------------------------------------------------
-- 4. Evidence commands (capture for the report — Phase 2 "after")
-- ---------------------------------------------------------------------
-- SHOW GRANTS FOR 'app_svc'@'192.168.56.20';
-- SHOW GRANTS FOR 'doctor_user'@'192.168.56.%' USING 'role_doctor';
-- SELECT user, host FROM mysql.user ORDER BY user;
