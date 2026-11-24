-- =====================================================================
--  Phase 14 — Tamper-evident audit log (hash chain)
--  Each audit row is chained to the previous row's hash:
--      row_hash = SHA256( prev_hash || canonical(row) )
--  Deleting, modifying or reordering any row breaks the chain from that
--  point on, which a verification pass detects — even if the tamperer is
--  a DBA. (A per-period HMAC "notarization" by the app, using an offline
--  audit key, prevents wholesale recomputation; see docs/phase14.)
-- =====================================================================
USE hospital;

ALTER TABLE audit_log
    ADD COLUMN prev_hash BINARY(32) NULL,
    ADD COLUMN row_hash  BINARY(32) NULL;

DELIMITER //
-- Compute the chain at insert time (fires for app inserts AND trigger inserts)
CREATE TRIGGER trg_audit_chain BEFORE INSERT ON audit_log
FOR EACH ROW
BEGIN
    DECLARE last_hash BINARY(32);
    SELECT row_hash INTO last_hash FROM audit_log ORDER BY log_id DESC LIMIT 1;
    IF last_hash IS NULL THEN SET last_hash = UNHEX(REPEAT('00',32)); END IF;
    SET NEW.prev_hash = last_hash;
    SET NEW.row_hash = UNHEX(SHA2(CONCAT_WS('|',
        HEX(last_hash),
        COALESCE(NEW.event_time,''), COALESCE(NEW.username,''), NEW.action,
        COALESCE(NEW.resource,''), COALESCE(NEW.resource_id,''), NEW.success,
        COALESCE(NEW.ip_address,'')), 256));
END//

-- Verification: returns the first row where the recomputed hash disagrees,
-- or no rows if the chain is intact.
CREATE PROCEDURE verify_audit_chain()
BEGIN
    SELECT a.log_id, a.event_time, a.username, a.action
    FROM audit_log a
    JOIN (SELECT log_id,
                 LAG(row_hash) OVER (ORDER BY log_id) AS expected_prev
          FROM audit_log) p ON p.log_id = a.log_id
    WHERE (p.expected_prev IS NOT NULL AND a.prev_hash <> p.expected_prev)
       OR a.row_hash <> UNHEX(SHA2(CONCAT_WS('|',
            HEX(a.prev_hash),
            COALESCE(a.event_time,''), COALESCE(a.username,''), a.action,
            COALESCE(a.resource,''), COALESCE(a.resource_id,''), a.success,
            COALESCE(a.ip_address,'')), 256))
    ORDER BY a.log_id LIMIT 1;
END//
DELIMITER ;
