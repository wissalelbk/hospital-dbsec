-- =====================================================================
--  Phase 7 — Auditing & Monitoring
--  Two complementary layers:
--    (a) APPLICATION log  (app/secure/audit.php): login success/failure,
--        sensitive-data access, logout, authorization denials — records the
--        human user, IP and user-agent.
--    (b) DATABASE triggers (below): record every modification/deletion of
--        clinical, financial and identity data — captured even if a change
--        is made directly in the DB, not through the app.
--  Together they answer: WHO / WHAT / WHEN / WHICH resource / SUCCESS?
--  The app sets @app_user per request (SET @app_user='alice'); triggers log
--  COALESCE(@app_user, CURRENT_USER()) so the human identity is preserved.
-- =====================================================================
USE hospital;

CREATE TABLE IF NOT EXISTS audit_log (
    log_id       BIGINT AUTO_INCREMENT PRIMARY KEY,
    event_time   DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    app_user_id  INT          NULL,
    db_user      VARCHAR(128) NULL,          -- CURRENT_USER() from triggers
    username     VARCHAR(64)  NULL,          -- human user (app or @app_user)
    action       VARCHAR(40)  NOT NULL,      -- LOGIN_SUCCESS, LOGIN_FAIL, UPDATE, DELETE, ...
    resource     VARCHAR(64)  NULL,          -- table / page
    resource_id  VARCHAR(64)  NULL,
    success      TINYINT(1)   NOT NULL DEFAULT 1,
    ip_address   VARCHAR(45)  NULL,
    user_agent   VARCHAR(255) NULL,
    details      JSON         NULL,          -- metadata only — NEVER sensitive plaintext
    INDEX idx_audit_time   (event_time),
    INDEX idx_audit_user   (username),
    INDEX idx_audit_action (action)
) ENGINE=InnoDB;

-- Append-only for the application account: INSERT only → it cannot erase or
-- alter its own tracks. (Supersedes the commented grant in db/04.)
GRANT INSERT ON hospital.audit_log TO 'app_svc'@'192.168.56.20';

-- ---------------------------------------------------------------------
-- Triggers on sensitive tables (record modification / deletion).
-- Details store only non-sensitive metadata (which row, by whom) — never
-- diagnosis text or decrypted values.
-- ---------------------------------------------------------------------
DELIMITER //

-- medical_records -------------------------------------------------------
CREATE TRIGGER trg_mr_ins AFTER INSERT ON medical_records FOR EACH ROW
INSERT INTO audit_log (db_user, username, action, resource, resource_id, success)
VALUES (CURRENT_USER(), @app_user, 'INSERT', 'medical_records', NEW.record_id, 1)//

CREATE TRIGGER trg_mr_upd AFTER UPDATE ON medical_records FOR EACH ROW
INSERT INTO audit_log (db_user, username, action, resource, resource_id, success, details)
VALUES (CURRENT_USER(), @app_user, 'UPDATE', 'medical_records', NEW.record_id, 1,
        JSON_OBJECT('diagnosis_changed', (OLD.diagnosis <=> NEW.diagnosis) = 0))//

CREATE TRIGGER trg_mr_del AFTER DELETE ON medical_records FOR EACH ROW
INSERT INTO audit_log (db_user, username, action, resource, resource_id, success)
VALUES (CURRENT_USER(), @app_user, 'DELETE', 'medical_records', OLD.record_id, 1)//

-- billing ---------------------------------------------------------------
CREATE TRIGGER trg_bill_upd AFTER UPDATE ON billing FOR EACH ROW
INSERT INTO audit_log (db_user, username, action, resource, resource_id, success, details)
VALUES (CURRENT_USER(), @app_user, 'UPDATE', 'billing', NEW.invoice_id, 1,
        JSON_OBJECT('status_old', OLD.status, 'status_new', NEW.status))//

CREATE TRIGGER trg_bill_del AFTER DELETE ON billing FOR EACH ROW
INSERT INTO audit_log (db_user, username, action, resource, resource_id, success)
VALUES (CURRENT_USER(), @app_user, 'DELETE', 'billing', OLD.invoice_id, 1)//

-- patients (PII) --------------------------------------------------------
CREATE TRIGGER trg_pat_upd AFTER UPDATE ON patients FOR EACH ROW
INSERT INTO audit_log (db_user, username, action, resource, resource_id, success)
VALUES (CURRENT_USER(), @app_user, 'UPDATE', 'patients', NEW.patient_id, 1)//

CREATE TRIGGER trg_pat_del AFTER DELETE ON patients FOR EACH ROW
INSERT INTO audit_log (db_user, username, action, resource, resource_id, success)
VALUES (CURRENT_USER(), @app_user, 'DELETE', 'patients', OLD.patient_id, 1)//

-- app_users (security-relevant: password / role / lockout changes) ------
CREATE TRIGGER trg_user_upd AFTER UPDATE ON app_users FOR EACH ROW
INSERT INTO audit_log (db_user, username, action, resource, resource_id, success, details)
VALUES (CURRENT_USER(), @app_user, 'ACCOUNT_CHANGE', 'app_users', NEW.user_id, 1,
        JSON_OBJECT('role_changed', (OLD.role_id <=> NEW.role_id) = 0,
                    'pw_changed',  (OLD.password_hash <=> NEW.password_hash) = 0,
                    'locked', NEW.locked_until IS NOT NULL))//

DELIMITER ;

-- ---------------------------------------------------------------------
-- Detection / investigation queries (used in Phase 10). Kept as views.
-- ---------------------------------------------------------------------
CREATE OR REPLACE VIEW v_failed_logins AS
    SELECT username, ip_address, COUNT(*) AS fails, MAX(event_time) AS last_try
    FROM audit_log WHERE action='LOGIN_FAIL'
    GROUP BY username, ip_address HAVING fails >= 3;

CREATE OR REPLACE VIEW v_sensitive_access AS
    SELECT event_time, username, action, resource, resource_id, ip_address
    FROM audit_log
    WHERE action IN ('VIEW_MEDICAL_RECORD','PATIENT_SEARCH','UPDATE','DELETE','ACCOUNT_CHANGE')
    ORDER BY event_time DESC;
