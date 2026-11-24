-- =====================================================================
--  Phase 19 (v3) — Audit notarization (closes the DBA-recompute gap)
--  The hash chain (Phase 14) detects naive tampering, but a DBA who knows
--  the scheme could delete a row and RECOMPUTE the whole chain to restore
--  internal consistency. Notarization defeats this: the app periodically
--  signs the current chain tip with an OFFLINE audit key (HMAC). A DBA
--  cannot forge the signature for a new tip, so any change to already-
--  notarized history is detected.
-- =====================================================================
USE hospital;

CREATE TABLE IF NOT EXISTS audit_notary (
    notary_id   INT AUTO_INCREMENT PRIMARY KEY,
    upto_log_id BIGINT NOT NULL,
    chain_hash  BINARY(32) NOT NULL,     -- row_hash of the latest row at notarization
    hmac_sig    BINARY(32) NOT NULL,     -- HMAC(audit_key, upto_log_id || chain_hash)
    created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB;

-- Simulation helper: what a sophisticated DBA would run to recompute the
-- entire chain after tampering (to try to restore internal consistency).
DROP PROCEDURE IF EXISTS sp_recompute_chain;
DELIMITER //
CREATE PROCEDURE sp_recompute_chain()
BEGIN
    DECLARE done INT DEFAULT 0;
    DECLARE v_id BIGINT; DECLARE v_prev BINARY(32) DEFAULT UNHEX(REPEAT('00',32));
    DECLARE cur CURSOR FOR SELECT log_id FROM audit_log ORDER BY log_id;
    DECLARE CONTINUE HANDLER FOR NOT FOUND SET done=1;
    OPEN cur;
    read_loop: LOOP
        FETCH cur INTO v_id;
        IF done THEN LEAVE read_loop; END IF;
        UPDATE audit_log SET prev_hash=v_prev,
            row_hash=UNHEX(SHA2(CONCAT_WS('|', HEX(v_prev),
                COALESCE(event_time,''), COALESCE(username,''), action,
                COALESCE(resource,''), COALESCE(resource_id,''), success,
                COALESCE(ip_address,'')),256))
            WHERE log_id=v_id;
        SELECT row_hash INTO v_prev FROM audit_log WHERE log_id=v_id;
    END LOOP;
    CLOSE cur;
END//
DELIMITER ;
