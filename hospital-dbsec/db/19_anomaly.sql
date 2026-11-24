-- =====================================================================
--  Phase 20 (v3) — Anomaly detection + automated response
--  Detects bulk access to sensitive data (possible exfiltration), raises a
--  tamper-evident ANOMALY_ALERT, and auto-locks the offending account.
--  Offenders are materialized into a temp table first, so the lock UPDATE
--  does not read audit_log while the account trigger writes to it.
-- =====================================================================
USE hospital;

DROP PROCEDURE IF EXISTS sp_detect_anomalies;
DELIMITER //
CREATE PROCEDURE sp_detect_anomalies(IN p_threshold INT, IN p_window_min INT)
BEGIN
    CREATE TEMPORARY TABLE IF NOT EXISTS _offenders (username VARCHAR(64) PRIMARY KEY, cnt INT);
    DELETE FROM _offenders;
    INSERT INTO _offenders
        SELECT username, COUNT(*) FROM audit_log
        WHERE action IN ('VIEW_MEDICAL_RECORD','PATIENT_SEARCH')
          AND event_time >= NOW() - INTERVAL p_window_min MINUTE
          AND username IS NOT NULL
        GROUP BY username HAVING COUNT(*) >= p_threshold;

    -- 1) raise alerts
    INSERT INTO audit_log (username, action, resource, success, details)
        SELECT username, 'ANOMALY_ALERT', 'audit_log', 1,
               JSON_OBJECT('reason','bulk_sensitive_access','count',cnt)
        FROM _offenders;

    -- 2) automated response: lock offending accounts (reads temp table, not audit_log)
    UPDATE app_users u JOIN _offenders o ON o.username = u.username
        SET u.locked_until = NOW() + INTERVAL 30 MINUTE;

    DROP TEMPORARY TABLE _offenders;
END//
DELIMITER ;

CREATE OR REPLACE VIEW v_anomalies AS
    SELECT event_time, username, JSON_EXTRACT(details,'$.count') AS access_count
    FROM audit_log WHERE action='ANOMALY_ALERT' ORDER BY event_time DESC;
-- Scheduled: SET GLOBAL event_scheduler=ON; then
-- CREATE EVENT IF NOT EXISTS ev_detect_anomalies ON SCHEDULE EVERY 1 MINUTE DO CALL sp_detect_anomalies(20,5);
